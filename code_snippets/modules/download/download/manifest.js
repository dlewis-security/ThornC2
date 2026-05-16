const manifest = {
  "title": "Download",
  "task_type": "download",
  "author": "ph3eds",
  "description": "Pull a file from the implant host to the C2 server.",
  "parameters": [
    {
      "name": "remote_path",
      "placeholder": "{{REMOTE_PATH}}",
      "type": "",
      "description": "Absolute path to the file on the implant host (e.g. C:\\Users\\Public\\loot.txt)",
      "default": ""
    },
    {
      "name": "local_path",
      "placeholder": "{{LOCAL_PATH}}",
      "type": "",
      "description": "Destination path on the C2 server where the file will be saved",
      "default": ""
    }
  ]
}
export { manifest }
