# WinGraph
 Graph Visualizer for Windows Event Logs

## Requirements
Uses the below Python libraries to produce visualizations and .graphml files for further analysis;
* pyvis
* networkx

Also uses the following libs;
* requests
* pyyaml

Additionally, relies on EvtxECmd by Eric Zimmerman for easy normalization of Windows Event Logs (automatically downloaded as part of program execution if it does not exist in the current working directory)
* https://github.com/EricZimmerman/evtx
