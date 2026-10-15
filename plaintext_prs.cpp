#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>
#include <iomanip>
#include <cmath>
#include <algorithm>

#ifdef _WIN32
#include <direct.h>
#define MKDIR(dir) _mkdir(dir)
#else
#include <sys/stat.h>
#define MKDIR(dir) mkdir(dir, 0755)
#endif

using namespace std;

// Helper to trim whitespace from strings
string Trim(const string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (string::npos == first) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

// Read CSV file into vector of double rows
vector<vector<double>> ReadCSV(const string& filename) {
    vector<vector<double>> data;
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "Error opening file: " << filename << endl;
        return data;
    }
    string line;
    bool firstLine = true;
    while (getline(file, line)) {
        // Strip UTF-8 BOM if present on the first line
        if (firstLine) {
            if (line.size() >= 3 &&
                (unsigned char)line[0] == 0xEF &&
                (unsigned char)line[1] == 0xBB &&
                (unsigned char)line[2] == 0xBF) {
                line = line.substr(3);
            }
            firstLine = false;
        }
        line = Trim(line);
        if (line.empty()) continue;
        if (line[0] == '#' || (line.size() >= 2 && line[0] == '/' && line[1] == '/')) continue;

        stringstream ss(line);
        string cell;
        vector<double> row;
        while (getline(ss, cell, ',')) {
            cell = Trim(cell);
            if (!cell.empty()) {
                try {
                    row.push_back(stod(cell));
                } catch (...) {
                    // Ignore non-numeric header cells
                }
            }
        }
        if (!row.empty()) {
            data.push_back(row);
        }
    }
    return data;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cerr << "Usage: " << argv[0] << " <beta.csv> <hospital1.csv> [hospital2.csv] ... [hospitalN.csv]" << endl;
        cerr << "Requires 1 beta file and at least 1 hospital file." << endl;
        return 1;
    }

    MKDIR("output");

    string betaFile = argv[1];
    vector<string> hospitalFiles;
    for (int i = 2; i < argc; ++i) {
        hospitalFiles.push_back(argv[i]);
    }
    size_t numHospitals = hospitalFiles.size();

    cout << "============================================================" << endl;
    cout << "          PLAINTEXT UNENCRYPTED PRS CALCULATOR              " << endl;
    cout << "============================================================" << endl;
    cout << "[CONFIG] Beta file: " << betaFile << endl;
    cout << "[CONFIG] Number of hospitals: " << numHospitals << endl;
    for (size_t i = 0; i < numHospitals; ++i) {
        cout << "[CONFIG] Hospital " << (i + 1) << " file: " << hospitalFiles[i] << endl;
    }

    auto startTotal = chrono::high_resolution_clock::now();

    // 1. Read Beta weights
    auto betaData = ReadCSV(betaFile);
    if (betaData.empty()) {
        cerr << "FATAL: Beta file '" << betaFile << "' is empty or missing. Aborting." << endl;
        return 1;
    }
    vector<double> betaRow = betaData[0];
    cout << "\n[MODEL OWNER] Loaded " << betaRow.size() << " beta weight values." << endl;

    // 2. Compute Plaintext PRS for each hospital
    vector<vector<double>> allPlaintextPRS(numHospitals);

    for (size_t h = 0; h < numHospitals; ++h) {
        cout << "\n--- Processing Hospital " << (h + 1) << " ---" << endl;
        auto genoData = ReadCSV(hospitalFiles[h]);
        if (genoData.empty()) {
            cerr << "WARNING: Hospital " << (h + 1) << " file '" << hospitalFiles[h]
                 << "' could not be opened or is empty. Skipping." << endl;
            continue;
        }

        size_t numPatients = genoData.size();
        cout << "[HOSPITAL " << (h + 1) << "] Loaded " << numPatients << " patients." << endl;

        string outFilename = "output/hospital" + to_string(h + 1) + "_prs_plaintext.csv";
        ofstream outFile(outFilename);
        outFile << scientific << setprecision(12);

        size_t commonLen = min(betaRow.size(), genoData[0].size());

        for (size_t p = 0; p < numPatients; ++p) {
            const auto& row = genoData[p];
            double prs = 0.0;
            size_t len = min(betaRow.size(), row.size());
            for (size_t i = 0; i < len; ++i) {
                prs += row[i] * betaRow[i];
            }
            allPlaintextPRS[h].push_back(prs);
            outFile << prs << "\n";
        } 

        outFile.close();
        cout << "[HOSPITAL " << (h + 1) << "] Saved plaintext PRS to " << outFilename << endl;
    }

    auto endTotal = chrono::high_resolution_clock::now();
    chrono::duration<double> diffTotal = endTotal - startTotal;
    cout << "\n[BENCHMARK] Plaintext PRS calculation finished in " << diffTotal.count() << " seconds." << endl;

    // 3. Error Analysis against Encrypted Results (if available)
    cout << "\n============================================================" << endl;
    cout << "           ERROR ANALYSIS (FHE vs. PLAINTEXT)              " << endl;
    cout << "============================================================" << endl;

    for (size_t h = 0; h < numHospitals; ++h) {
        string encryptedFilename = "output/hospital" + to_string(h + 1) + "_prs.csv";
        auto encryptedData = ReadCSV(encryptedFilename);

        if (encryptedData.empty()) {
            cout << "Hospital " << (h + 1) << ": Encrypted output '" << encryptedFilename 
                 << "' not found. (Run multiparty_prs1 first to enable error comparison)" << endl;
            continue;
        }

        vector<double> fhePRS;
        for (const auto& r : encryptedData) {
            if (!r.empty()) fhePRS.push_back(r[0]);
        }

        const auto& plainPRS = allPlaintextPRS[h];
        size_t count = min(fhePRS.size(), plainPRS.size());

        if (count == 0) {
            cout << "Hospital " << (h + 1) << ": No matching patient entries to compare." << endl;
            continue;
        }

        double maxAbsErr = 0.0;
        double sumAbsErr = 0.0;
        double sumSqErr = 0.0;
        double maxRelErrPercent = 0.0;

        for (size_t p = 0; p < count; ++p) {
            double absErr = std::abs(fhePRS[p] - plainPRS[p]);
            maxAbsErr = std::max(maxAbsErr, absErr);
            sumAbsErr += absErr;
            sumSqErr += absErr * absErr;

            if (std::abs(plainPRS[p]) > 1e-15) {
                double relErr = (absErr / std::abs(plainPRS[p])) * 100.0;
                maxRelErrPercent = std::max(maxRelErrPercent, relErr);
            }
        }

        double mae = sumAbsErr / count;
        double rmse = std::sqrt(sumSqErr / count);

        cout << "--- Hospital " << (h + 1) << " (" << count << " patients compared) ---" << endl;
        cout << fixed << setprecision(8);
        cout << "  Mean Absolute Error (MAE):  " << mae << endl;
        cout << "  Root Mean Sq. Error (RMSE): " << rmse << endl;
        cout << "  Max Absolute Error:        " << maxAbsErr << endl;
        cout << "  Max Relative Error:        " << maxRelErrPercent << " %" << endl;
    }

    cout << "============================================================" << endl;
    return 0;
}
