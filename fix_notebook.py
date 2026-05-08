import json
import re

nb_path = r'd:\a study A\spring 26\Copy_of_CSE422_project_spring26.ipynb'

with open(nb_path, 'r', encoding='utf-8') as f:
    nb = json.load(f)

for cell in nb.get('cells', []):
    if cell.get('cell_type') != 'code':
        continue
    
    source = ''.join(cell.get('source', []))
    new_source = source
    
    # 1. MinMaxScaler fix
    if 'scaler = MinMaxScaler()' in new_source:
        new_source = new_source.replace('scaler = MinMaxScaler()', 'minmax_scaler = MinMaxScaler()')
        new_source = new_source.replace('scaler.fit(X_train)', 'minmax_scaler.fit(X_train)')
        new_source = new_source.replace('X_train_scaled = scaler.transform(X_train)', 'X_train_minmax = minmax_scaler.transform(X_train)')
        new_source = new_source.replace('X_test_scaled = scaler.transform(X_test)', 'X_test_minmax = minmax_scaler.transform(X_test)')
        new_source = new_source.replace('X_train_scaled.min', 'X_train_minmax.min')
        new_source = new_source.replace('X_train_scaled.max', 'X_train_minmax.max')

    # 2. KNN after scaling
    if 'knn.fit(X_train_scaled, y_train)' in new_source:
        new_source = new_source.replace('X_train_scaled', 'X_train_minmax')
        new_source = new_source.replace('X_test_scaled', 'X_test_minmax')
        
    # 3. Logreg after scaling
    if 'log_reg.fit(X_train_scaled, y_train)' in new_source:
        new_source = new_source.replace('X_train_scaled', 'X_train_minmax')
        new_source = new_source.replace('X_test_scaled', 'X_test_minmax')
        
    # 4. StandardScaler / MLP
    if 'scaler = StandardScaler()' in new_source:
        new_source = new_source.replace('scaler = StandardScaler()', 'std_scaler = StandardScaler()')
        new_source = new_source.replace('X_train_scaled = scaler.fit_transform(X_train)', 'X_train_std = std_scaler.fit_transform(X_train)')
        new_source = new_source.replace('X_test_scaled = scaler.transform(X_test)', 'X_test_std = std_scaler.transform(X_test)')
        new_source = new_source.replace('mlp.fit(X_train_scaled, y_train)', 'mlp.fit(X_train_std, y_train)')
        new_source = new_source.replace('mlp.score(X_test_scaled, y_test)', 'mlp.score(X_test_std, y_test)')
        
    # 5. Precision / Recall
    if 'y_pred_knn = knn.predict(X_test)' in new_source:
        new_source = new_source.replace('y_pred_knn = knn.predict(X_test)', 'y_pred_knn = knn.predict(X_test_minmax)')
        new_source = new_source.replace('y_pred_log = log_reg.predict(X_test)', 'y_pred_log = log_reg.predict(X_test_minmax)')
        new_source = new_source.replace('y_pred_nn = mlp.predict(X_test)', 'y_pred_nn = mlp.predict(X_test_std)')
        
    # 6. Confusion Matrix
    if 'y_pred = model.predict(X_test_scaled)' in new_source:
        replacement = '''    if name in ["KNN", "Logistic Regression"]:
        X_eval = X_test_minmax
    elif name == "Neural Network":
        X_eval = X_test_std
    else:
        X_eval = X_test
    y_pred = model.predict(X_eval)'''
        new_source = new_source.replace('    y_pred = model.predict(X_test_scaled) # over scaled obvi', replacement)
        
    # 7. ROC AUC 1
    if 'y_score = model.predict_proba(X_test)[:,1]' in new_source and 'Neural Net' in new_source:
        replacement = '''    if name in ["KNN", "Logistic Regression"]:
        X_eval = X_test_minmax
    elif name == "Neural Net":
        X_eval = X_test_std
    else:
        X_eval = X_test

    if hasattr(model, "predict_proba"):
        y_score = model.predict_proba(X_eval)[:,1]   # prob for cls1
    else:
        y_score = model.decision_function(X_eval)    # fallback'''
        # using regex to replace the if-else block
        new_source = re.sub(r'    # check if model can output probabilities.*?    else:\n        y_score = model\.decision_function\(X_test\)    # fallback', replacement, new_source, flags=re.DOTALL)

    # 8. ROC AUC 2
    if 'y_score = model.predict_proba(X_test)[:, 1]' in new_source and 'dt: dt' in new_source:
        replacement = '''    if name in ["knn", "logreg"]:
        X_eval = X_test_minmax
    elif name == "nn":
        X_eval = X_test_std
    else:
        X_eval = X_test
        
    if hasattr(model, "predict_proba"):
        y_score = model.predict_proba(X_eval)[:, 1]
    else:
        y_score = model.decision_function(X_eval)'''
        new_source = re.sub(r'    if hasattr\(model, "predict_proba"\):.*?    else:\n        y_score = model\.decision_function\(X_test\)', replacement, new_source, flags=re.DOTALL)

    if source != new_source:
        # reconstruct the source array
        # split by newline, keeping the newline character except for the last line if it didn't have one
        lines = new_source.splitlines(True)
        cell['source'] = lines

with open(nb_path, 'w', encoding='utf-8') as f:
    json.dump(nb, f, indent=2, ensure_ascii=False)

print("Notebook fixed!")
