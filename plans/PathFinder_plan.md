# ViperACL: Pathfinder Module Blueprint

## 1. Directory Structure
Based on the existing ViperACL project architecture, the Pathfinder module will reside in its own dedicated directory. This ensures high modularity and keeps the codebase simple and readable.

```text
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
```

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

1. Random Forest (The Current Prototype Baseline)
- Concept: Builds dozens of independent decision trees and averages their predictions.
- Implementation Effort: Low (Uses flattened tabular data via Scikit-Learn).
- Advantages: Extremely fast to train; naturally handles non-linear paradoxes (like our Sync Delay); highly interpretable for academic defense.
- Disadvantages: Suffers from the "Order Blindspot" (cannot differentiate AddMember -> GenericWrite from GenericWrite -> AddMember); loses all graph structure context.
- Performance Impact: Excellent baseline. Provides a massive operational accuracy boost over static heuristics (like traditional Dijkstra/A*).

2. XGBoost (eXtreme Gradient Boosting)
- Concept: Builds decision trees sequentially, where every new tree specifically focuses on correcting the errors of the previous tree.
- Implementation Effort: Low (Drop-in Python replacement for Random Forest).
- Advantages: The absolute industry standard for tabular data; provides incredibly accurate "Feature Importance" metrics (perfect for proving which exploits are statistically the most dangerous).
- Disadvantages: Still suffers from the same "Order Blindspot" as Random Forest; slightly easier to overfit if the training dataset is too small.
- Performance Impact: Typically yields a 5% to 15% accuracy boost over Random Forest with minimal code changes.

3. LSTM (Long Short-Term Memory Neural Networks)
- Concept: A Recurrent Neural Network (RNN) designed to process data as a chronological sequence rather than a flat list.
- Implementation Effort: Medium-High (Requires PyTorch/TensorFlow and reshaping data into time-steps).
- Advantages: Completely solves the "Order Blindspot." It remembers previous steps, meaning it mathematically understands the operational sequence of an attack.
- Disadvantages: "Black Box" architecture makes it very hard to explain why it scored a path a certain way to a supervisor; slower to train.
- Performance Impact: Massive boost in sequential accuracy. It will flawlessly penalize bad exploit chains while rewarding stealthy, logically ordered chains.

4. Graph Neural Networks (GNN)
- Concept: Operates directly on nodes and edges. It does not compress the data; it learns the actual topology of the network.
- Implementation Effort: Extremely High (Requires PyTorch Geometric and deep integration with the graph database).
- Advantages: Understands "Neighborhood Risk." It can see if an attack path safely avoids a highly monitored IT Organizational Unit (OU) or if it blindly walks right through a cluster of honeypot accounts.
- Disadvantages: Computationally heavy; very complex mathematical implementation.
- Performance Impact: The Holy Grail of Active Directory analysis. Yields the absolute maximum theoretical accuracy because it evaluates structural topology directly.

Random Forest (Our Current Prototype): "Proves our core concept by successfully detecting 'toxic combinations' of exploits, showing that AI can penalize paths where two safe steps actually cause an operational failure when combined."

XGBoost (The Performance Upgrade): "Provides maximum predictive accuracy and generates clear 'Feature Importance' metrics, giving us mathematical proof of which specific Active Directory exploits are the most dangerous overall."

LSTM Neural Networks (The Sequence Master): "Solves the 'Order Blindspot' by reading attack paths like a timeline, allowing the AI to understand that executing Step A before Step B succeeds, but reversing the order causes an automation crash."

Graph Neural Networks / GNN (The Ultimate Future Work): "Analyzes the actual physical topology of the network rather than just a list of steps, allowing the AI to dynamically route attackers safely around highly monitored or dangerous 'neighborhoods' in the domain."