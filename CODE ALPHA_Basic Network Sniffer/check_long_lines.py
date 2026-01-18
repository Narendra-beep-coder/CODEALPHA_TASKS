import sys
p = sys.argv[1]
with open(p, 'r', encoding='utf-8') as f:
    for i, line in enumerate(f, start=1):
        ln = line.rstrip('\n')
        if len(ln) > 79:
            print(f"{i}: {len(ln)}: {ln}")
