with open("TIE-Bomber-ASCII-Art.txt", "r", encoding="utf-8") as f:
    lines = f.readlines()

print('printf("', end="")
for line in lines:
    line = line.rstrip("\n").replace("\\", "\\\\").replace("\"", '\\"')
    print(line + "\\n", end="")

print('");')
