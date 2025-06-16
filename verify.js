// verify.js

// This script uses the built-in 'node:util' module to parse command-line arguments.
// It has NO EXTERNAL NPM DEPENDENCIES.
const { parseArgs } = require('node:util');

/**
 * Manually parses key fields from a raw SGX quote buffer.
 * The SGX quote structure is well-defined, allowing us to read offsets directly.
 * @param {Buffer} quoteBuffer The raw quote binary.
 * @returns {{mrenclave: Buffer, mrsigner: Buffer, reportData: Buffer}}
 */
function parseQuoteManually(quoteBuffer) {
    const HEADER_SIZE = 48;
    const MRENCLAVE_OFFSET = 112; // Offset within the 384-byte report body
    const MRSIGNER_OFFSET = 176;  // Offset within the 384-byte report body
    const REPORT_DATA_OFFSET = 320; // Offset within the 384-byte report body
    const HASH_SIZE = 32;
    const REPORT_DATA_SIZE = 64;

    const mrenclave = quoteBuffer.subarray(HEADER_SIZE + MRENCLAVE_OFFSET, HEADER_SIZE + MRENCLAVE_OFFSET + HASH_SIZE);
    const mrsigner = quoteBuffer.subarray(HEADER_SIZE + MRSIGNER_OFFSET, HEADER_SIZE + MRSIGNER_OFFSET + HASH_SIZE);
    const reportData = quoteBuffer.subarray(HEADER_SIZE + REPORT_DATA_OFFSET, HEADER_SIZE + REPORT_DATA_OFFSET + REPORT_DATA_SIZE);

    return { mrenclave, mrsigner, reportData };
}

/**
 * Simulates the full cryptographic verification of the quote.
 * In a production environment, this function would use Intel's DCAP QVL libraries.
 * @param {Buffer} quoteBuffer The raw quote binary.
 * @returns {Promise<boolean>}
 */
async function performFullCryptographicVerification(quoteBuffer) {
    console.log("\n--- [SIMULATION] Performing Full Cryptographic Verification ---");
    console.log("INFO: In a production system, this step uses Intel's DCAP libraries to verify the quote's signature and trust chain against the PCCS.");
    // For this example, we simulate a successful verification. DO NOT DO THIS IN PRODUCTION.
    const isVerified = true;
    console.log(`INFO: Simulation result: ${isVerified ? 'SUCCESS' : 'FAILURE'}`);
    console.log("------------------------------------------------------------\n");
    return isVerified;
}

/**
 * The main verification function.
 */
async function main() {
    // 1. Define and parse command-line arguments
    const argOptions = {
        quote: { type: 'string' },
        expected_mrenclave_hex: { type: 'string' },
        expected_mrsigner_hex: { type: 'string' },
    };

    const { values: args } = parseArgs({ options: argOptions });

    // 2. Validate that all required arguments were provided
    if (!args.quote || !args.expected_mrenclave_hex || !args.expected_mrsigner_hex) {
        console.error("ERROR: Missing one or more required arguments.");
        console.error("\nUsage:");
        console.error("  node verify.js --quote <base64_quote> --expected_mrenclave_hex <hex_string> --expected_mrsigner_hex <hex_string>");
        console.error("\nExample:");
        console.error('  node verify.js --quote "AAM..." --expected_mrenclave_hex "c1a..." --expected_mrsigner_hex "83d..."');
        process.exit(1);
    }

    try {
        const quoteBuffer = Buffer.from(args.quote, 'base64');

        // 3. Perform the full cryptographic verification (Simulated)
        const isCryptoVerified = await performFullCryptographicVerification(quoteBuffer);
        if (!isCryptoVerified) {
            console.error("[-] VERIFICATION FAILED: The quote's cryptographic signature or trust chain is invalid.");
            process.exit(1);
        }
        console.log("[+] Cryptographic verification of the quote was successful.");

        // 4. Parse the now-trusted quote to inspect its contents
        const { mrenclave, mrsigner, reportData } = parseQuoteManually(quoteBuffer);
        const mrenclaveHex = mrenclave.toString('hex');
        const mrsignerHex = mrsigner.toString('hex');
        const reportDataHex = reportData.toString('hex');

        console.log("\n--- Enclave Details from Quote ---");
        console.log(`MRENCLAVE:   ${mrenclaveHex}`);
        console.log(`MRSIGNER:    ${mrsignerHex}`);
        console.log(`REPORT DATA: ${reportDataHex}`);
        console.log("----------------------------------\n");

        // 5. Application-Specific Logic: Compare with expected values from arguments
        console.log("--- Comparing with Expected Values ---");
        const isMrenclaveMatch = (mrenclaveHex === args.expected_mrenclave_hex);
        const isMrsignerMatch = (mrsignerHex === args.expected_mrsigner_hex);

        console.log(`MRENCLAVE matches expected value: ${isMrenclaveMatch ? 'YES' : 'NO'}`);
        console.log(`MRSIGNER matches expected value:  ${isMrsignerMatch ? 'YES' : 'NO'}`);
        console.log("------------------------------------\n");
        
        // Final decision
        if (isMrenclaveMatch && isMrsignerMatch) {
            console.log("[SUCCESS] The enclave has been successfully verified. It is the correct software from the correct publisher.");
        } else {
            console.error("[FAILURE] The enclave is NOT TRUSTED. MRENCLAVE or MRSIGNER did not match.");
            process.exit(1);
        }

    } catch (error) {
        if (error.code === 'ERR_INVALID_ARG_VALUE') {
             console.error("ERROR: Invalid Base64 input for --quote. Please check the quote string.");
        } else {
             console.error("An error occurred during verification:", error.message);
        }
        process.exit(1);
    }
}

main();
