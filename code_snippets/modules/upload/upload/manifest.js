const manifest = {
  "title": "Upload",
  "task_type": "upload",
  "author": "ph3eds",
  "description": "Push a file from the C2 server to the implant host.",
  "parameters": [
    {
      "name": "local_path",
      "placeholder": "{{LOCAL_PATH}}",
      "type": "",
      "description": "Absolute path to the file on the C2 server",
      "default": ""
    },
    {
      "name": "remote_path",
      "placeholder": "{{REMOTE_PATH}}",
      "type": "",
      "description": "Destination path on the implant host (e.g. C:\\Users\\Public\\file.exe)",
      "default": ""
    }
  ]
}
export { manifest }
