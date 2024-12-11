## Building and Running

1. Build the Docker image:
   ```bash
   docker build -t rwslotmachine2 .
   ```


2. Run the Docker image:
   ```bash
   docker run -p 31345:31345 rwslotmachine2
   ```

3. Test with the Python exploit:
   ```bash
   python3 sol_got_overwrite.py
   ```
