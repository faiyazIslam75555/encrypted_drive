import json

with open(r'd:\a study A\spring 26\Copy_of_CSE422_project_spring26.ipynb', encoding='utf-8') as f:
    nb = json.load(f)

with open('scratch_source.py', 'w', encoding='utf-8') as f:
    f.write('\n'.join([''.join(c.get('source', [])) for c in nb.get('cells', []) if c.get('cell_type')=='code']))
