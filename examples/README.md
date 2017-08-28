# Examples

## Sample schtasks.exe XML

The sample task will attempt to run every minute. It will not run if the task is already running.

This task requires SYSTEM or Local Administrator access to create. Be sure to customize the path before you use it.

The task XML can be imported with the following command line:

```
schtasks /create /xml <filename> /tn <taskname>
```
