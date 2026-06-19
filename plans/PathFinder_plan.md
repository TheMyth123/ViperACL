# ViperACL: Pathfinder Module Blueprint

## 1. Directory Structure
Based on the existing ViperACL project architecture, the Pathfinder module will reside in its own dedicated directory. This ensures high modularity and keeps the codebase simple and readable.

ViperACL/
├── core/
│   ├── pathfinder/             
│   │   ├── __init__.py         
│   │   ├── pathfinder.py       # MAIN COORDINATOR: Routes requests to engines
│   │   ├── fasttrack.py        # ENGINE 1: Hop-Optimized (Cypher ShortestPath)
│   │   ├── tactical.py         # ENGINE 2: Cost-Weighted (Cypher REDUCE)
│   │   ├── predictive.py       # ENGINE 3: ML-Driven (Scikit-Learn)
│   │   └── train_model.py      # ML Trainer Script
│   └── ingestor/
│       └── parser.py           # SharpHound JSON to Neo4j Parser
├── data/
│   └── synthetic_training.csv  # Labeled Paradox Data
└── models/
    └── viper_rf_model.pkl      # Trained Random Forest Brain

FastTrack is blind to risk. It only sees Length.

Tactical is blind to length. It only sees Static Cost.

Predictive (ML) balances both based on Historical Training Data.

### 2. The Supervisor Presentation Script (Point-Form)

Use this script while the terminal output is visible on the screen. It guides the supervisor through exactly *why* the AI is necessary.

**Introduction**
* "To demonstrate the core value of ViperACL, I engineered a specific Active Directory environment and asked three different pathfinding engines to compromise the target."
* "Standard mapping tools just draw all the lines. ViperACL decides which line an automated script should actually take."

**Analyzing Engine 1: Viper FastTrack**
* "First, we have the FastTrack engine. As you can see, it found a very short, 2-hop path."
* "However, it relies entirely on the `ForceChangePassword` exploit. In a real corporate network, resetting two administrators' passwords will immediately lock them out, instantly alerting the Security Operations Center (SOC)."
* "FastTrack is mathematically correct but operationally dangerous."

**Analyzing Engine 2: Viper Tactical**
* "Next, I built the Tactical engine. It uses a static cost calculator to avoid noisy exploits."
* "It chose a 4-hop path with a very low static cost of 2, relying heavily on `MemberOf` and `AddMember`."
* "A static calculator thinks this is the perfect path. But it suffers from a hidden Active Directory trap: **The Sync Delay Paradox**."
* "When an automated script executes `AddMember`, the AD replication and Kerberos token generation take time. Because the script immediately fires the next exploit (`GenericWrite`), the token hasn't updated yet, and the automation crashes with an `Access Denied` error."

**Analyzing Engine 3: Viper Predictive (The ML Solution)**
* "This brings us to the Machine Learning Predictive engine, the core of my research."
* "I trained a Random Forest model on historical data that explicitly contained these operational paradoxes."
* "Notice that the ML engine reviewed the Tactical engine's path, recognized the toxic `AddMember -> GenericWrite` combination, and heavily penalized it, dropping its success probability to just **36%** (Rank 3)."
* "It reviewed the FastTrack path, saw the extreme noise, and dropped it to **22%** (Rank 4)."
* "Instead, the AI dynamically routed us through Rank 1: a 3-hop path utilizing only `GenericWrite`. It learned that this specific chain balances execution speed with a high automation reliability, yielding an **80% success probability**."
* "This proves that ViperACL doesn't just calculate math; it understands the operational reality of automated penetration testing."