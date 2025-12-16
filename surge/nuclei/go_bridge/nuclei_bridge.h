#ifndef NUCLEI_BRIDGE_H
#define NUCLEI_BRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

// Callback function types - Python provides these function pointers
typedef void (*VulnCallback)(char* jsonData);
typedef void (*ProgressCallback)(char* jsonData);
typedef void (*StateCallback)(char* jsonData);
typedef void (*ErrorCallback)(char* jsonData);

// Initialize a new Nuclei engine
// useThreadSafe: 0 = regular engine, 1 = ThreadSafeNucleiEngine
char* InitializeNucleiEngine(char* engineID, char* configJSON, int useThreadSafe);

// Register callbacks for real-time monitoring
// Call this BEFORE ExecuteScan to receive callbacks
char* RegisterCallbacks(char* engineID, char* scanID,
                        VulnCallback vulnCB, ProgressCallback progressCB,
                        StateCallback stateCB, ErrorCallback errorCB);

// Execute a scan with targets (callbacks must be registered first)
char* ExecuteScan(char* engineID, char* targetsJSON);

// Control scan execution
char* PauseScan(char* engineID);
char* ResumeScan(char* engineID);
char* AdjustRateLimit(char* engineID, int rateLimit);

// Get current scan state (real-time statistics)
char* GetScanState(char* engineID);

// Cleanup
char* CloseEngine(char* engineID);

#ifdef __cplusplus
}
#endif

#endif // NUCLEI_BRIDGE_H
