//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>
#include <iomanip>
#include <map>
#include <algorithm>
#include <cctype>

#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#include <psapi.h>
#define MKDIR(dir) _mkdir(dir)
static double GetPeakMemoryUsageMB() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return static_cast<double>(pmc.PeakWorkingSetSize) / (1024.0 * 1024.0);
    }
    return 0.0;
}
#else
#include <sys/stat.h>
#include <sys/resource.h>
#define MKDIR(dir) mkdir(dir, 0755)
static double GetPeakMemoryUsageMB() {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
#ifdef __APPLE__
        return static_cast<double>(usage.ru_maxrss) / (1024.0 * 1024.0);
#else
        return static_cast<double>(usage.ru_maxrss) / 1024.0;
#endif
    }
    return 0.0;
}
#endif
//2^13 = 8, 2^14 
#include "openfhe.h"

using namespace lbcrypto;
using namespace std;

// Helper functions
string Trim(const string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (string::npos == first) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

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
        // Skip comment lines
        if (line[0] == '#' || (line.size() >= 2 && line[0] == '/' && line[1] == '/')) continue;

        stringstream ss(line);
        string cell;
        vector<double> row;
        while (getline(ss, cell, ',')) {
            cell = Trim(cell);
            if (!cell.empty()) {
                try {
                    row.push_back(stod(cell));
                } catch (const std::exception& e) {
                    cerr << "Warning: skipping invalid value '" << cell << "' in " << filename << endl;
                }
            }
        }
        if (!row.empty()) {
            data.push_back(row);
        }
    }
    return data;
}
//1 row is 1 patient
vector<Ciphertext<DCRTPoly>> EncryptChunkedRow(CryptoContext<DCRTPoly>& cc, const vector<double>& row, const PublicKey<DCRTPoly>& publicKey, uint32_t batchSize) {
    vector<Ciphertext<DCRTPoly>> chunks;
    for (size_t i = 0; i < row.size(); i += batchSize) {
        vector<double> chunk(row.begin() + i, row.begin() + min(row.size(), (size_t)i + batchSize));
        if (chunk.size() < batchSize) {
            chunk.resize(batchSize, 0.0);
        }
        Plaintext pt = cc->MakeCKKSPackedPlaintext(chunk);
        chunks.push_back(cc->Encrypt(publicKey, pt));
    }
    return chunks;
}

Ciphertext<DCRTPoly> EvalPRSFromChunks(CryptoContext<DCRTPoly>& cc, const vector<Ciphertext<DCRTPoly>>& genoChunks, const vector<Ciphertext<DCRTPoly>>& betaChunks, uint32_t batchSize) {
    if (genoChunks.empty() || betaChunks.empty() || genoChunks.size() != betaChunks.size()) {
        throw runtime_error("Chunk sizes mismatch or empty in EvalPRSFromChunks");
    }
    
    Ciphertext<DCRTPoly> prs = cc->EvalMult(genoChunks[0], betaChunks[0]);
    for (size_t i = 1; i < genoChunks.size(); ++i) {
        prs = cc->EvalAdd(prs, cc->EvalMult(genoChunks[i], betaChunks[i]));
    }
    
    prs = cc->EvalSum(prs, batchSize); //prs here is a polynomial 
    return prs;
}

double ThresholdDecrypt(CryptoContext<DCRTPoly>& cc, const Ciphertext<DCRTPoly>& ciphertext, const vector<KeyPair<DCRTPoly>>& kps) {
    auto ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertext}, kps[0].secretKey);
    vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
    partialCiphertextVec.push_back(ciphertextPartial1[0]);

    for (size_t i = 1; i < kps.size(); i++) {
        auto ciphertextPartial = cc->MultipartyDecryptMain({ciphertext}, kps[i].secretKey);
        partialCiphertextVec.push_back(ciphertextPartial[0]);
    }
    //lead + main keys are combined to get the final fusion ley
    Plaintext plaintextMultiparty;
    cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultiparty);
    plaintextMultiparty->SetLength(1);
    auto vals = plaintextMultiparty->GetCKKSPackedValue();
    return vals.empty() ? 0.0 : std::real(vals[0]);
}

void RunFederatedPRS(uint32_t ringDim, uint32_t multDepth, uint32_t scaleModSize, const string& betaFile, const vector<string>& hospitalFiles) {
    int numHospitals = hospitalFiles.size();
    uint32_t batchSize = ringDim / 2;

    cout << "============================================================" << endl;
    cout << "  MULTI-PARTY CKKS FEDERATED PRS SYSTEM" << endl;
    cout << "============================================================" << endl;
    cout << "[CONFIG] Ring dimension: " << ringDim << endl;
    cout << "[CONFIG] Batch size: " << batchSize << endl;
    cout << "[CONFIG] Multiplicative depth: " << multDepth << endl;
    cout << "[CONFIG] Scale modulus size: " << scaleModSize << endl;
    cout << "[CONFIG] Number of hospitals: " << numHospitals << endl;
    cout << "[CONFIG] Beta file: " << betaFile << endl;
    for (int i = 0; i < numHospitals; i++) {
        cout << "[CONFIG] Hospital " << i + 1 << " file: " << hospitalFiles[i] << endl;
    }

    MKDIR("output");
    MKDIR("logs");

    ofstream logFile("logs/runtime.txt");
    auto timeStart = chrono::high_resolution_clock::now();
    time_t now = time(nullptr);
    logFile << "Federated PRS Run Started: " << ctime(&now);
    logFile << "RingDim: " << ringDim << ", MultDepth: " << multDepth << ", ScaleModSize: " << scaleModSize << "\n";
    logFile << "Number of Hospitals: " << numHospitals << "\n";

    cout << "\n--- Phase 1: CKKS Context Setup ---" << endl;
    auto t1_start = chrono::high_resolution_clock::now();

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetRingDim(ringDim);
    parameters.SetStandardDeviation(3.2);
    parameters.SetSecretKeyDist(UNIFORM_TERNARY);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetDigitSize(30);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);

    auto t1_end = chrono::high_resolution_clock::now();
    chrono::duration<double> t1_diff = t1_end - t1_start;
    logFile << "Phase 1 (Setup): " << t1_diff.count() << " s\n";

    cout << "\n--- Phase 2: N-Party Key Generation ---" << endl;
    auto t2_start = chrono::high_resolution_clock::now();

    vector<KeyPair<DCRTPoly>> kps(numHospitals);
    kps[0] = cc->KeyGen();  // lead party
    for (int i = 1; i < numHospitals; i++) {
        kps[i] = cc->MultipartyKeyGen(kps[i-1].publicKey);
    }
    auto jointPublicKey = kps[numHospitals-1].publicKey;

    auto t2_end = chrono::high_resolution_clock::now();
    chrono::duration<double> t2_diff = t2_end - t2_start;
    logFile << "Phase 2 (KeyGen): " << t2_diff.count() << " s\n";

    cout << "\n--- Phase 3: EvalMult Key Aggregation (N-party) ---" << endl;
    auto t3_start = chrono::high_resolution_clock::now();

    auto evalMultKey = cc->KeySwitchGen(kps[0].secretKey, kps[0].secretKey);
    vector<EvalKey<DCRTPoly>> evalMultKeys(numHospitals);
    evalMultKeys[0] = evalMultKey;
    for (int i = 1; i < numHospitals; i++) {
        evalMultKeys[i] = cc->MultiKeySwitchGen(kps[i].secretKey, kps[i].secretKey, evalMultKey);
    }

    auto accum = evalMultKeys[0];
    for (int i = 1; i < numHospitals; i++) {
        accum = cc->MultiAddEvalKeys(accum, evalMultKeys[i], kps[i].publicKey->GetKeyTag());
    }

    vector<EvalKey<DCRTPoly>> multiMultKeys(numHospitals);
    for (int i = 0; i < numHospitals; i++) {
        multiMultKeys[i] = cc->MultiMultEvalKey(kps[i].secretKey, accum, jointPublicKey->GetKeyTag());
    }

    auto multiAccum = multiMultKeys[numHospitals - 1];
    for (int i = numHospitals - 2; i >= 0; i--) {
        multiAccum = cc->MultiAddEvalMultKeys(multiMultKeys[i], multiAccum, jointPublicKey->GetKeyTag());
    }
    cc->InsertEvalMultKey({multiAccum});

    auto t3_end = chrono::high_resolution_clock::now();
    chrono::duration<double> t3_diff = t3_end - t3_start;
    logFile << "Phase 3 (EvalMult KeyGen): " << t3_diff.count() << " s\n";

    cout << "\n--- Phase 4: EvalSum Key Aggregation (N-party) ---" << endl;
    auto t4_start = chrono::high_resolution_clock::now();

    cc->EvalSumKeyGen(kps[0].secretKey);
    auto evalSumKeys = make_shared<map<usint, EvalKey<DCRTPoly>>>(cc->GetEvalSumKeyMap(kps[0].secretKey->GetKeyTag()));

    vector<shared_ptr<map<usint, EvalKey<DCRTPoly>>>> evalSumKeysVec(numHospitals);
    evalSumKeysVec[0] = evalSumKeys;
    for (int i = 1; i < numHospitals; i++) {
        evalSumKeysVec[i] = cc->MultiEvalSumKeyGen(kps[i].secretKey, evalSumKeys, kps[i].publicKey->GetKeyTag());
    }

    auto sumAccum = evalSumKeysVec[0];
    for (int i = 1; i < numHospitals; i++) {
        sumAccum = cc->MultiAddEvalSumKeys(sumAccum, evalSumKeysVec[i], kps[i].publicKey->GetKeyTag());
    }
    cc->InsertEvalSumKey(sumAccum);

    auto t4_end = chrono::high_resolution_clock::now();
    chrono::duration<double> t4_diff = t4_end - t4_start;
    logFile << "Phase 4 (EvalSum KeyGen): " << t4_diff.count() << " s\n";

    cout << "\n--- Phase 5: Read Data and Encrypt ---" << endl;
    auto t5_start = chrono::high_resolution_clock::now();

    auto betaData = ReadCSV(betaFile);
    if (betaData.empty()) {
        cerr << "Error: beta file is empty or missing." << endl;
        return;
    }
    vector<double> betaRow = betaData[0];
    cout << "[MODEL OWNER] Beta weights loaded: " << betaRow.size() << " SNPs" << endl;
    cout << "[MODEL OWNER] Encrypting beta with joint public key..." << endl;
    auto betaChunks = EncryptChunkedRow(cc, betaRow, jointPublicKey, batchSize);
    cout << "[MODEL OWNER] Beta encrypted into " << betaChunks.size() << " ciphertext chunk(s)" << endl;

    vector<vector<vector<Ciphertext<DCRTPoly>>>> hospitalEncryptedData(numHospitals);
    vector<int> patientCounts(numHospitals);

    for (int h = 0; h < numHospitals; ++h) {
        auto genoData = ReadCSV(hospitalFiles[h]);
        if (genoData.empty()) {
            cerr << "FATAL: Hospital " << h + 1 << " file '" << hospitalFiles[h]
                 << "' could not be opened or contains no data. Aborting." << endl;
            return;
        }
        patientCounts[h] = genoData.size();
        cout << "[HOSPITAL " << h + 1 << "] Loaded " << patientCounts[h] << " patients from " << hospitalFiles[h] << endl;
        cout << "[HOSPITAL " << h + 1 << "] Encrypting genotype data with joint public key..." << endl;
        hospitalEncryptedData[h].resize(patientCounts[h]);
        #pragma omp parallel for schedule(dynamic)
        for (int p = 0; p < patientCounts[h]; ++p) {
            hospitalEncryptedData[h][p] = EncryptChunkedRow(cc, genoData[p], jointPublicKey, batchSize);
        }
        cout << "[HOSPITAL " << h + 1 << "] Encryption complete." << endl;
    }

    auto t5_end = chrono::high_resolution_clock::now();
    chrono::duration<double> t5_diff = t5_end - t5_start;
    logFile << "Phase 5 (Read & Encrypt): " << t5_diff.count() << " s\n";

    cout << "\n--- Phase 6: Homomorphic PRS Evaluation ---" << endl;
    auto t6_start = chrono::high_resolution_clock::now();

    vector<vector<Ciphertext<DCRTPoly>>> hospitalEncryptedPRS(numHospitals);

    for (int h = 0; h < numHospitals; ++h) {
        cout << "Hospital " << h + 1 << ": Computing PRS for " << patientCounts[h] << " patients..." << endl;
        hospitalEncryptedPRS[h].resize(patientCounts[h]);
        #pragma omp parallel for schedule(dynamic)
        for (int p = 0; p < patientCounts[h]; ++p) {
            hospitalEncryptedPRS[h][p] = EvalPRSFromChunks(cc, hospitalEncryptedData[h][p], betaChunks, batchSize);
        }
    }

    auto t6_end = chrono::high_resolution_clock::now();
    chrono::duration<double> t6_diff = t6_end - t6_start;
    logFile << "Phase 6 (Evaluation): " << t6_diff.count() << " s\n";

    cout << "\n--- Phase 7 & 8: Threshold Decryption and Output ---" << endl;
    auto t7_start = chrono::high_resolution_clock::now();

    for (int h = 0; h < numHospitals; ++h) {
        vector<double> prsResults(patientCounts[h]);
        #pragma omp parallel for schedule(dynamic)
        for (int p = 0; p < patientCounts[h]; ++p) {
            prsResults[p] = ThresholdDecrypt(cc, hospitalEncryptedPRS[h][p], kps);
        }
        //1200 patients -> 400+400+400
        //distance function for isolation outputs, distance remains same after homomorphic computation
        //genomic data and beta weights are encrypted, so no privacy leakage
        //skip abstract intro for now
        //notations, preliminaries(openFHE lib, CKKS algo, multiparty threshold ckks), motivation
        //N hospitals, 1 model owner, 1 beta file, N hospital files, plaintext PRS computation, federated PRS computation
        //Flowchart, pseudocode, implementation, experiments(skip for now), results, conclusion, future work
        // Write results sequentially to preserve patient ordering
        string outFilename = "output/hospital" + to_string(h + 1) + "_prs.csv";
        ofstream outFile(outFilename);
        outFile << scientific << setprecision(12);
        for (int p = 0; p < patientCounts[h]; ++p) {
            outFile << prsResults[p] << "\n";
            // cout << "  Hospital " << h + 1 << " Patient " << p + 1 << "/" << patientCounts[h] << " -> " << prsResults[p] << endl; //commenting out to reduce console clutter
        }
        outFile.close();
        logFile << "Hospital " << h + 1 << " patient count: " << patientCounts[h] << "\n";
    }

    auto t7_end = chrono::high_resolution_clock::now();
    chrono::duration<double> t7_diff = t7_end - t7_start;
    logFile << "Phase 7 & 8 (Decryption & Output): " << t7_diff.count() << " s\n";

    auto timeEnd = chrono::high_resolution_clock::now();
    chrono::duration<double> totalTime = timeEnd - timeStart;

    double peakMemoryMB = GetPeakMemoryUsageMB();
    logFile << "Peak Memory Usage: " << fixed << setprecision(2) << peakMemoryMB << " MB (" << (peakMemoryMB / 1024.0) << " GB)\n";
    logFile << "Total Time: " << totalTime.count() << " s\n";
    logFile.close();

    cout << "\n============================================================" << endl;
    cout << "Peak Memory Usage: " << fixed << setprecision(2) << peakMemoryMB << " MB (" << (peakMemoryMB / 1024.0) << " GB)" << endl;
    cout << "Done! Total time : " << setprecision(4) << totalTime.count() << " s" << endl;
    cout << "============================================================" << endl;
}

int main(int argc, char* argv[]) {
    if (argc < 6) {
        cerr << "Usage: " << argv[0] << " <ringDim> <multDepth> <scaleModSize> <beta.csv> <hospital1.csv> <hospital2.csv> ... [hospitalN.csv]" << endl;
        cerr << "Minimum 2 hospitals required." << endl;
        return 1;
    }

    uint32_t ringDim = stoul(argv[1]);
    uint32_t multDepth = stoul(argv[2]);
    uint32_t scaleModSize = stoul(argv[3]);
    string betaFile = argv[4];

    vector<string> hospitalFiles;
    for (int i = 5; i < argc; i++) {
        hospitalFiles.push_back(argv[i]);
    }

    if (hospitalFiles.size() < 2) {
        cerr << "Error: Minimum 2 hospitals required." << endl;
        return 1;
    }

    RunFederatedPRS(ringDim, multDepth, scaleModSize, betaFile, hospitalFiles);

    return 0;
}