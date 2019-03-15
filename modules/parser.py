import json
file = open("", "r+")
for line in file.readlines() :
  string = line.replace("\n", "")
  string='{"timestamp":"1550794171","name":"0.175.17.109.rev.sfr.net","type":"a","value":"109.17.175.0"}'
  load = json.loads(string)
  if load["name"] :
    name = load["name"]
    if load["type"] :
      typ = load["type"]
      print(name, typ)
