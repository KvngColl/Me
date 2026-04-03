import java.util.*;

/**
 * HeistChessSim
 *
 * Basic project:
 * - Board modeled like chess (8x8) with role-specific move sets
 * - Team roles map to piece logic: King, Queen, Rook, Bishop, Knight, Pawn
 * - Objectives: Vault (must be reached), optional Data + Exit
 * - Dynamic danger field from guards + cameras (line-of-sight pressure)
 * - A* pathfinding per agent with per-step risk weighting
 * - Monte Carlo scenario noise to score and rank candidate plans
 *
 * Run:
 *   javac HeistChessSim.java
 *   java HeistChessSim
 */
public class HeistChessSim {

    enum PieceType { KING, QUEEN, ROOK, BISHOP, KNIGHT, PAWN }

    static final class Pos {
        final int r;
        final int c;

        Pos(int r, int c) {
            this.r = r;
            this.c = c;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Pos)) return false;
            Pos p = (Pos) o;
            return r == p.r && c == p.c;
        }

        @Override
        public int hashCode() {
            return (r << 3) ^ c;
        }

        @Override
        public String toString() {
            return "(" + r + "," + c + ")";
        }
    }

    static final class Agent {
        final String name;
        final PieceType type;
        final Pos start;

        Agent(String name, PieceType type, Pos start) {
            this.name = name;
            this.type = type;
            this.start = start;
        }

        @Override
        public String toString() {
            return name + "[" + type + "]@" + start;
        }
    }

    static final class Plan {
        final String id;
        final List<Agent> team;
        final boolean takeData;
        final boolean requireExit;

        Plan(String id, List<Agent> team, boolean takeData, boolean requireExit) {
            this.id = id;
            this.team = team;
            this.takeData = takeData;
            this.requireExit = requireExit;
        }
    }

    static final class Route {
        final List<Pos> path;
        final double pathRisk;

        Route(List<Pos> path, double pathRisk) {
            this.path = path;
            this.pathRisk = pathRisk;
        }
    }

    static final class Outcome {
        final Plan plan;
        final double successRate;
        final double expectedLoot;
        final double expectedHeat;
        final double expectedTurns;
        final int simulatedRuns;

        Outcome(Plan plan, double successRate, double expectedLoot, double expectedHeat, double expectedTurns, int simulatedRuns) {
            this.plan = plan;
            this.successRate = successRate;
            this.expectedLoot = expectedLoot;
            this.expectedHeat = expectedHeat;
            this.expectedTurns = expectedTurns;
            this.simulatedRuns = simulatedRuns;
        }
    }

    static final class Grid {
        final int N = 8;
        final boolean[][] blocked = new boolean[N][N];
        final double[][] baseDanger = new double[N][N];

        final Pos entry = new Pos(7, 0);
        final Pos vault = new Pos(0, 7);
        final Pos data = new Pos(2, 3);
        final Pos exit = new Pos(7, 7);

        Grid() {
            initObstacles();
            initDanger();
        }

        private void initObstacles() {
            int[][] walls = {
                {6, 2}, {6, 3}, {5, 3}, {4, 3},
                {2, 5}, {3, 5}, {4, 5}, {1, 1},
                {2, 1}, {3, 1}, {5, 6}
            };
            for (int[] w : walls) blocked[w[0]][w[1]] = true;

            // Keep objective squares open.
            blocked[entry.r][entry.c] = false;
            blocked[vault.r][vault.c] = false;
            blocked[data.r][data.c] = false;
            blocked[exit.r][exit.c] = false;
        }

        private void initDanger() {
            // Guard posts and camera rays induce pressure gradients.
            List<Pos> guards = Arrays.asList(new Pos(1, 6), new Pos(4, 1), new Pos(6, 6));
            List<Pos> cameras = Arrays.asList(new Pos(0, 4), new Pos(3, 7));

            for (Pos g : guards) {
                for (int r = 0; r < N; r++) {
                    for (int c = 0; c < N; c++) {
                        int md = Math.abs(r - g.r) + Math.abs(c - g.c);
                        baseDanger[r][c] += 1.4 / (1.0 + md);
                    }
                }
            }

            // Camera line pressure in rook directions with obstacle attenuation.
            int[][] dirs = {{1,0},{-1,0},{0,1},{0,-1}};
            for (Pos cam : cameras) {
                baseDanger[cam.r][cam.c] += 2.0;
                for (int[] d : dirs) {
                    int rr = cam.r + d[0], cc = cam.c + d[1], depth = 1;
                    while (inside(rr, cc) && !blocked[rr][cc]) {
                        baseDanger[rr][cc] += 2.8 / (1.0 + depth * 0.8);
                        rr += d[0];
                        cc += d[1];
                        depth++;
                    }
                }
            }
        }

        boolean inside(int r, int c) {
            return r >= 0 && r < N && c >= 0 && c < N;
        }
    }

    static List<Pos> movesFor(PieceType t, Pos p, Grid g) {
        List<Pos> out = new ArrayList<>();
        switch (t) {
            case KING:
                for (int dr = -1; dr <= 1; dr++) {
                    for (int dc = -1; dc <= 1; dc++) {
                        if (dr == 0 && dc == 0) continue;
                        addIfValid(out, p.r + dr, p.c + dc, g);
                    }
                }
                break;
            case KNIGHT:
                int[][] k = {{2,1},{1,2},{-1,2},{-2,1},{-2,-1},{-1,-2},{1,-2},{2,-1}};
                for (int[] m : k) addIfValid(out, p.r + m[0], p.c + m[1], g);
                break;
            case PAWN:
                // Heist pawn can move forward (toward row 0) and capture-diagonal style sidesteps.
                addIfValid(out, p.r - 1, p.c, g);
                addIfValid(out, p.r - 1, p.c - 1, g);
                addIfValid(out, p.r - 1, p.c + 1, g);
                break;
            case ROOK:
                ray(out, p, g, 1, 0);
                ray(out, p, g, -1, 0);
                ray(out, p, g, 0, 1);
                ray(out, p, g, 0, -1);
                break;
            case BISHOP:
                ray(out, p, g, 1, 1);
                ray(out, p, g, 1, -1);
                ray(out, p, g, -1, 1);
                ray(out, p, g, -1, -1);
                break;
            case QUEEN:
                ray(out, p, g, 1, 0);
                ray(out, p, g, -1, 0);
                ray(out, p, g, 0, 1);
                ray(out, p, g, 0, -1);
                ray(out, p, g, 1, 1);
                ray(out, p, g, 1, -1);
                ray(out, p, g, -1, 1);
                ray(out, p, g, -1, -1);
                break;
        }
        return out;
    }

    static void ray(List<Pos> out, Pos from, Grid g, int dr, int dc) {
        int r = from.r + dr;
        int c = from.c + dc;
        while (g.inside(r, c) && !g.blocked[r][c]) {
            out.add(new Pos(r, c));
            r += dr;
            c += dc;
        }
    }

    static void addIfValid(List<Pos> out, int r, int c, Grid g) {
        if (g.inside(r, c) && !g.blocked[r][c]) out.add(new Pos(r, c));
    }

    static Route aStar(Grid g, PieceType t, Pos start, Pos goal, double[][] dynamicDanger) {
        PriorityQueue<Node> open = new PriorityQueue<>(Comparator.comparingDouble(n -> n.f));
        Map<Pos, Double> gScore = new HashMap<>();
        Map<Pos, Pos> parent = new HashMap<>();

        gScore.put(start, 0.0);
        open.add(new Node(start, heuristic(start, goal), 0.0));

        while (!open.isEmpty()) {
            Node cur = open.poll();
            if (cur.p.equals(goal)) {
                List<Pos> path = reconstruct(parent, cur.p);
                double risk = 0.0;
                for (Pos step : path) risk += dynamicDanger[step.r][step.c];
                return new Route(path, risk);
            }

            for (Pos nx : movesFor(t, cur.p, g)) {
                double moveCost = 1.0 + dynamicDanger[nx.r][nx.c] * 0.9;
                double cand = gScore.get(cur.p) + moveCost;
                Double old = gScore.get(nx);
                if (old == null || cand < old) {
                    parent.put(nx, cur.p);
                    gScore.put(nx, cand);
                    double f = cand + heuristic(nx, goal);
                    open.add(new Node(nx, f, cand));
                }
            }
        }
        return null;
    }

    static final class Node {
        final Pos p;
        final double f;
        final double g;

        Node(Pos p, double f, double g) {
            this.p = p;
            this.f = f;
            this.g = g;
        }
    }

    static double heuristic(Pos a, Pos b) {
        return Math.abs(a.r - b.r) + Math.abs(a.c - b.c);
    }

    static List<Pos> reconstruct(Map<Pos, Pos> parent, Pos end) {
        LinkedList<Pos> rev = new LinkedList<>();
        Pos cur = end;
        rev.addFirst(cur);
        while (parent.containsKey(cur)) {
            cur = parent.get(cur);
            rev.addFirst(cur);
        }
        return rev;
    }

    static double[][] dynamicDanger(Grid g, Random rnd) {
        double[][] d = new double[g.N][g.N];
        for (int r = 0; r < g.N; r++) {
            for (int c = 0; c < g.N; c++) {
                double jitter = (rnd.nextDouble() - 0.5) * 0.35;
                d[r][c] = Math.max(0.0, g.baseDanger[r][c] * (1.0 + jitter));
                if (g.blocked[r][c]) d[r][c] += 9.0;
            }
        }
        return d;
    }

    static Outcome simulatePlan(Plan plan, Grid g, int runs, long seed) {
        Random rnd = new Random(seed);

        int success = 0;
        double lootTotal = 0.0;
        double heatTotal = 0.0;
        double turnsTotal = 0.0;

        for (int i = 0; i < runs; i++) {
            double[][] dd = dynamicDanger(g, rnd);

            // Assign first agent to vault objective anchor.
            Agent lead = plan.team.get(0);
            Route toVault = aStar(g, lead.type, lead.start, g.vault, dd);
            if (toVault == null) continue;

            double routeRisk = toVault.pathRisk;
            int turns = toVault.path.size() - 1;

            // Optional side objective by second agent.
            if (plan.takeData && plan.team.size() > 1) {
                Agent support = plan.team.get(1);
                Route toData = aStar(g, support.type, support.start, g.data, dd);
                if (toData == null) continue;
                routeRisk += toData.pathRisk * 0.75;
                turns += Math.max(0, toData.path.size() - 1);
            }

            // Optional extraction objective by third agent (or lead fallback).
            if (plan.requireExit) {
                Agent ex = plan.team.size() > 2 ? plan.team.get(2) : lead;
                Route toExit = aStar(g, ex.type, ex.start, g.exit, dd);
                if (toExit == null) continue;
                routeRisk += toExit.pathRisk * 0.8;
                turns += Math.max(0, toExit.path.size() - 1);
            }

            // Team synergy: diversified movement capabilities reduce detection overlap.
            double diversity = pieceDiversity(plan.team);
            double cohesion = 0.82 + 0.28 * diversity;

            // Convert risk profile to success probability.
            double logistic = 1.0 / (1.0 + Math.exp((routeRisk / Math.max(1.0, turns)) - 2.65));
            double p = clamp(logistic * cohesion - 0.015 * turns + rnd.nextGaussian() * 0.03, 0.0, 1.0);

            boolean ok = rnd.nextDouble() < p;
            if (ok) {
                success++;
                double baseLoot = 1200 + rnd.nextDouble() * 3500;
                if (plan.takeData) baseLoot += 900 + rnd.nextDouble() * 700;
                if (plan.requireExit) baseLoot += 300;
                lootTotal += baseLoot * (0.8 + 0.4 * p);
            }

            double heat = routeRisk * (0.45 + (ok ? 0.25 : 0.55));
            heatTotal += heat;
            turnsTotal += turns;
        }

        return new Outcome(
            plan,
            runs == 0 ? 0.0 : (double) success / runs,
            runs == 0 ? 0.0 : lootTotal / runs,
            runs == 0 ? 0.0 : heatTotal / runs,
            runs == 0 ? 0.0 : turnsTotal / runs,
            runs
        );
    }

    static double pieceDiversity(List<Agent> team) {
        Set<PieceType> s = new HashSet<>();
        for (Agent a : team) s.add(a.type);
        return (double) s.size() / Math.max(1, team.size());
    }

    static double clamp(double x, double lo, double hi) {
        return Math.max(lo, Math.min(hi, x));
    }

    static List<Plan> candidatePlans(Grid g) {
        Agent ghost = new Agent("Ghost", PieceType.KNIGHT, g.entry);
        Agent queen = new Agent("Cipher", PieceType.QUEEN, g.entry);
        Agent rook = new Agent("Bulwark", PieceType.ROOK, g.entry);
        Agent bishop = new Agent("Shade", PieceType.BISHOP, g.entry);
        Agent king = new Agent("Anchor", PieceType.KING, g.entry);
        Agent pawn = new Agent("Runner", PieceType.PAWN, g.entry);

        List<Plan> plans = new ArrayList<>();
        plans.add(new Plan("A-ShadowFork", Arrays.asList(queen, ghost, bishop), true, true));
        plans.add(new Plan("B-IronRail", Arrays.asList(rook, king, pawn), false, true));
        plans.add(new Plan("C-GlassNeedle", Arrays.asList(bishop, ghost, queen), true, false));
        plans.add(new Plan("D-QuietCastle", Arrays.asList(king, rook, bishop), false, false));
        plans.add(new Plan("E-VoltKnight", Arrays.asList(ghost, queen, rook), true, true));
        return plans;
    }

    static void printMap(Grid g) {
        char[][] m = new char[g.N][g.N];
        for (int r = 0; r < g.N; r++) {
            for (int c = 0; c < g.N; c++) m[r][c] = g.blocked[r][c] ? '#' : '.';
        }
        m[g.entry.r][g.entry.c] = 'S';
        m[g.vault.r][g.vault.c] = 'V';
        m[g.data.r][g.data.c] = 'D';
        m[g.exit.r][g.exit.c] = 'E';

        System.out.println("Map legend: S=start V=vault D=data E=exit #=wall");
        for (int r = 0; r < g.N; r++) {
            for (int c = 0; c < g.N; c++) System.out.print(m[r][c] + " ");
            System.out.println();
        }
    }

    public static void main(String[] args) {
        Grid g = new Grid();
        printMap(g);

        int runs = 1400;
        if (args.length > 0) {
            try {
                runs = Math.max(100, Integer.parseInt(args[0]));
            } catch (NumberFormatException ignored) {
                // Keep default if invalid user input.
            }
        }

        List<Plan> plans = candidatePlans(g);
        List<Outcome> ranked = new ArrayList<>();

        long seedBase = 1337L;
        for (int i = 0; i < plans.size(); i++) {
            ranked.add(simulatePlan(plans.get(i), g, runs, seedBase + i * 97));
        }

        ranked.sort((a, b) -> {
            double scoreA = a.successRate * 0.55 + (a.expectedLoot / 4000.0) * 0.35 - (a.expectedHeat / 25.0) * 0.10;
            double scoreB = b.successRate * 0.55 + (b.expectedLoot / 4000.0) * 0.35 - (b.expectedHeat / 25.0) * 0.10;
            return Double.compare(scoreB, scoreA);
        });

        System.out.println();
        System.out.println("=== Ranked Heist Plans (Chess Logic + Monte Carlo) ===");
        for (int i = 0; i < ranked.size(); i++) {
            Outcome o = ranked.get(i);
            System.out.printf(
                "%d) %-14s success=%6.2f%%  loot=%8.1f  heat=%6.2f  turns=%5.2f  team=%s%n",
                i + 1,
                o.plan.id,
                o.successRate * 100.0,
                o.expectedLoot,
                o.expectedHeat,
                o.expectedTurns,
                o.plan.team
            );
        }

        Outcome best = ranked.get(0);
        System.out.println();
        System.out.println("Recommended plan: " + best.plan.id);
        System.out.println("Objective profile: vault=" + true + ", data=" + best.plan.takeData + ", exit=" + best.plan.requireExit);
        System.out.println("Simulated runs: " + best.simulatedRuns);
    }
}
