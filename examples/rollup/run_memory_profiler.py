import subprocess
process = subprocess.Popen(['go', 'test', '-v', '-count', '1',  '-run',  '^TestCircuitFull$',
                            'github.com/consensys/gnark/examples/rollup'],
                           stdout=subprocess.PIPE,
                           bufsize=1)
for line in iter(process.stdout.readline, b''):
    print(line.decode('utf-8'))

process.wait()
