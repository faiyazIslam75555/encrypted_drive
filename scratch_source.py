#
# Importing Required Python libraries

import pandas as pd # dataset handle korbo
import matplotlib.pyplot as plt # plot korbo
import seaborn as sns # correlation
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

# loading dataset
dataset = pd.read_csv("/content/drive/MyDrive/E-commerce Shipping Dataset.csv")

dataset.head(10)
print ('Shape of the dataset is {}. This dataset contains {} rows and {} columns.'.format(dataset.shape,dataset.shape[0],dataset.shape[1]))
dataset.info()
#### selecting numerical features
numerical_data = dataset.select_dtypes(include='number')
numerical_features=numerical_data.columns.tolist()

print(f'There are {len(numerical_features)} numerical features:', '\n')
print(numerical_features)
#Selecting categoricalfeatures
categorical_data=dataset.select_dtypes(include= 'object')
categorical_features=categorical_data.columns.tolist()

print(f'There are {len(categorical_features)} categorical features:', '\n')
print(categorical_features)

print("\n--- Minimum and Maximum values for checking corrupt numbers ---")##checking if there are any corupt valuse or not?
print(dataset.describe().loc[['min', 'max']])


print("\n--- Unique values in Categorical Columns ---")
cat_cols = dataset.select_dtypes(include=['object']).columns
for col in cat_cols:
    print(f"{col}: {dataset[col].unique()}")
if 'ID' in dataset.columns:###Delete ID colum
    dataset = dataset.drop('ID', axis=1)
dataset.head(10)
print ('Shape of the dataset is {}. This dataset contains {} rows and {} columns.'.format(dataset.shape,dataset.shape[0],dataset.shape[1]))
# PROBLEM 1: Null / Missing values
# ==========================================
missing_values = dataset.isnull().sum()
print("Missing values in each column:\n", missing_values)
# PROBLEM 2: Categorical values

# Identify which columns are categorical (object type)
cat_cols = dataset.select_dtypes(include=['object']).columns.tolist()
print("\nCategorical columns to encode:", cat_cols)
# 1. Warehouse_block= nominal; hence one hot encoding
dataset = pd.get_dummies(dataset, columns=['Warehouse_block'], drop_first=False)
dataset.head()

print ('Shape of the dataset is {}. This dataset contains {} rows and {} columns.'.format(dataset.shape,dataset.shape[0],dataset.shape[1]))
dataset.head(5)
# 2. Mode_of_Shipment = nominal; hence one hot encoding
dataset = pd.get_dummies(dataset, columns=['Mode_of_Shipment'], drop_first=False)
dataset.head()

print ('Shape of the dataset is {}. This dataset contains {} rows and {} columns.'.format(dataset.shape,dataset.shape[0],dataset.shape[1]))
dataset.head(5)
dataset['Product_importance enc'] = dataset['Product_importance'].map({'low': 0, 'medium': 1, 'high': 2})
print(dataset[['Product_importance', 'Product_importance enc']].head(30))

print ('Shape of the dataset is {}. This dataset contains {} rows and {} columns.'.format(dataset.shape,dataset.shape[0],dataset.shape[1]))
# 4. Gender = nominal; hence one hot encoding
dataset = pd.get_dummies(dataset, columns=['Gender'], drop_first=False)
dataset.head()

print ('Shape of the dataset is {}. This dataset contains {} rows and {} columns.'.format(dataset.shape,dataset.shape[0],dataset.shape[1]))
categorical_features = [
    "Product_importance"
]
dataset = dataset.drop(columns=categorical_features)
dataset.head(4)
# Shifting Target Column to the Last

# ১. 'Reached.on.Time_Y.N' kete target e rakhlam
target = dataset.pop('Reached.on.Time_Y.N')

# same name e save kore e last e rakhlam
dataset['Reached.on.Time_Y.N'] = target


dataset.head(5)
dataset

print ('Shape of the dataset is {}. This dataset contains {} rows and {} columns.'.format(dataset.shape,dataset.shape[0],dataset.shape[1]))
dataset_corr = dataset.corr()
dataset_corr
sns.heatmap(dataset_corr, cmap = 'YlGnBu')
import matplotlib.pyplot as plt

# Counting and plotting the class distribution for your target feature
dataset["Reached.on.Time_Y.N"].value_counts().sort_index().plot(
    kind="bar",
    xlabel="Class (0 = On Time, 1 = Late)",
    ylabel="Number of Instances",
    rot=0,

)

# Adding a title to the graph
plt.title("Class Distribution of Target Feature (Reached.on.Time_Y.N)")

#plt.show()
# # Transposed stats for numerical features
numerical_data.describe().T
# Transposed stats for categorical features

categorical_data.describe().T
numerical_data.var()
dataset.var()
numerical_data.skew()
dataset.skew()
dataset
numerical_data.hist(figsize=(12,12),bins=20)
plt.show()
import matplotlib.pyplot as plt
import seaborn as sns

# Select only numerical columns for boxplot analysis
numeric_cols = dataset.select_dtypes(include=['int64', 'float64']).columns

# Set up the figure
plt.figure(figsize=(20, 30))

# Plot boxplots for each numerical feature including the target variable 'OUTCOME'
for i, col in enumerate(numeric_cols, 1):
    plt.subplot(len(numeric_cols), 1, i)
    sns.boxplot(x=dataset[col], color='skyblue')
    plt.title(f'Boxplot of {col}', fontsize=12)
    plt.tight_layout()

plt.show()
dataset
numerical_data.nunique()
numerical_data.isnull().sum()
# unique values counts
unique_counts=categorical_data.nunique()
print(unique_counts)
for col in categorical_features:
    plt.title(f'Distribution of {col}')
    categorical_data[col].value_counts().sort_index().plot(kind='bar', rot=0, xlabel=col,ylabel='count')
    plt.show()
# Calculate the correlation matrix
correlation_matrix = numerical_data.corr()
correlation_matrix

# Plotting the heatmap for correlation matrix
plt.figure(figsize=(8, 6))
sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', fmt='.3f', linewidths=0.3)
plt.show()
import matplotlib.pyplot as plt
import seaborn as sns

fig, ax = plt.subplots(3, 1, figsize=(10, 20)) # figsize
## ## Correlation coefficient using different methods
corr1 = dataset.corr('pearson')[['Reached.on.Time_Y.N']].sort_values(by='Reached.on.Time_Y.N', ascending=False)
corr2 = dataset.corr('spearman')[['Reached.on.Time_Y.N']].sort_values(by='Reached.on.Time_Y.N', ascending=False)
corr3 = dataset.corr('kendall')[['Reached.on.Time_Y.N']].sort_values(by='Reached.on.Time_Y.N', ascending=False)

# make the title for each
ax[0].set_title('Pearson Method', fontsize=14, fontweight='bold')
ax[1].set_title('Spearman Method', fontsize=14, fontweight='bold')
ax[2].set_title('Kendall Method', fontsize=14, fontweight='bold')

#Make the Heatmap
sns.heatmap(corr1, ax=ax[0], annot=True, cmap='coolwarm')
sns.heatmap(corr2, ax=ax[1], annot=True, cmap='coolwarm')
sns.heatmap(corr3, ax=ax[2], annot=True, cmap='coolwarm')

plt.tight_layout()
plt.show()
numerical_data.plot(kind='density',figsize=(14,14),subplots=True,layout=(6,2),title="Density plot of Numerical features",sharex=False)
plt.show()
from sklearn.model_selection import train_test_split

# x er moddhe target baad  e sob input
x = dataset.drop(columns='Reached.on.Time_Y.N')

# y only output column
y = dataset['Reached.on.Time_Y.N']

# data split 80,20
X_train, X_test, y_train, y_test = train_test_split(
    x, y,
    test_size=0.20,
    random_state=1,
    stratify=dataset['Reached.on.Time_Y.N']
)

print("Training data shape (X_train):", X_train.shape)
print("Testing data shape (X_test):", X_test.shape)
from sklearn.preprocessing import MinMaxScaler
scaler = MinMaxScaler()
scaler.fit(X_train)

# transform train data
X_train_scaled = scaler.transform(X_train)

# transform test data
X_test_scaled = scaler.transform(X_test)
print("per-feature minimum after scaling:\n {}".format(
    X_train_scaled.min(axis=0)))
print("per-feature maximum after scaling:\n {}".format(
    X_train_scaled.max(axis=0)))
# preprocessing before scaling
from sklearn.neighbors import KNeighborsClassifier
knn=KNeighborsClassifier()

knn.fit(X_train, y_train)
knn_accuracy_1 = knn.score(X_test, y_test)
print("Test set accuracy without scaling: {:.2f}".format(knn_accuracy_1))
# preprocessing after scaling
knn.fit(X_train_scaled, y_train)
knn_accuracy_2 = knn.score(X_test_scaled, y_test)
# scoring on the scaled test set
print("Test set accuracy after Min-Max Scaling: {:.2f}".format(
    knn_accuracy_2))
accuracy = {}
accuracy['knn'] = max(knn_accuracy_1, knn_accuracy_2)
accuracy
# logistic regression before scaling
from sklearn.linear_model import LogisticRegression
log_reg = LogisticRegression(max_iter=9000, solver='saga')  # 'saga' also works for large datasets
log_reg.fit(X_train, y_train)

logreg_accuracy_1 = log_reg.score(X_test, y_test)
print("Test set accuracy (Logistic Regression): {:.2f}".format(logreg_accuracy_1))
# logistic regression after scaling
from sklearn.linear_model import LogisticRegression
log_reg = LogisticRegression(max_iter=9000, solver='saga')
log_reg.fit(X_train_scaled, y_train)

logreg_accuracy_2 =  log_reg.score(X_test_scaled, y_test)
# Scoring on the scaled test set
print("Test set accuracy after Min-Max Scaling (Logistic Regression): {:.2f}".format(
   logreg_accuracy_2))
accuracy["logreg"] = max(logreg_accuracy_1, logreg_accuracy_2)
# before scaling feature
from sklearn.neural_network import MLPClassifier

mlp = MLPClassifier(hidden_layer_sizes=(50, 30),  # 2 hidden layers with 50 and 30 neurons
                    activation='relu',
                    solver='adam',
                    max_iter=9000,
                    random_state=0)

# Train the model
mlp.fit(X_train, y_train)
nn_accuracy_1 = mlp.score(X_test, y_test)
# Evaluate
print("Test set accuracy with Neural Network: {:.2f}".format(nn_accuracy_1))
## after scaling feature
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler # cuz it works better for relu
scaler = StandardScaler()
# transform train data
X_train_scaled = scaler.fit_transform(X_train)

# transform test data
X_test_scaled = scaler.transform(X_test)

mlp = MLPClassifier(hidden_layer_sizes=(50, 30),  # 2 hidden layers with 50 and 30 neurons
                    activation='relu',
                    solver='adam',
                    max_iter=9000,
                    random_state=0)

# Train the model
mlp.fit(X_train_scaled, y_train)
nn_accuracy_2 = mlp.score(X_test_scaled, y_test)
# Evaluate
print("Test set accuracy with Neural Network: {:.2f}".format(nn_accuracy_2))
accuracy["nn"] = max(nn_accuracy_1, nn_accuracy_2)
from sklearn import tree
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt

# 1. Separate features (x) and the target (y)
x = dataset.drop(columns='Reached.on.Time_Y.N')
y = dataset['Reached.on.Time_Y.N']

# 2. Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(
    x, y,
    test_size=0.20,
    random_state=1,
    stratify=dataset['Reached.on.Time_Y.N']
)

print("Training data shape:", X_train.shape)
print("Testing data shape:", X_test.shape)

# 3. Initialize and train (fit) the Decision Tree Classifier
dt = tree.DecisionTreeClassifier()
dt = dt.fit(X_train, y_train)

# 4. Plot the Decision Tree
plt.figure(figsize=(20, 10)) # Makes the plot large enough to read
tree.plot_tree(
    dt,
    filled=True, # Adds colors to the nodes
    feature_names=x.columns, # Shows the actual column names in the boxes
    class_names=['On Time', 'Late'], # Maps 0 and 1 to actual text
    rounded=True
)
plt.show()
# accuracy calculation
from sklearn.metrics import accuracy_score
y_pred = dt.predict(X_test)

# Accuracy
acc = accuracy_score(y_test, y_pred)
print("Decision Tree Accuracy:", acc)
accuracy["dt"] = acc
print(accuracy)
# K_Means_cluster
from sklearn.cluster import KMeans

def implement_KMC(df_temp,cluster_num):
  km = KMeans(n_clusters=cluster_num)  #defining the cluster number
  y_predicted = km.fit_predict(df_temp[df_temp.columns])
  return km,y_predicted #returns the model and the predicted assigned cluster to each entry

cluster = 2
dataset_kmeans = x
km,y_predicted = implement_KMC(dataset_kmeans,cluster)  ##stores the model and the predicted values
dataset_kmeans["kmeans_cluster"]=y_predicted
dataset_kmeans.head(10)
## before scaling

#Plot the 2 clusters with different color from the prediciton value
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans

# Run KMeans with 2 clusters
kmeans = KMeans(n_clusters=2, random_state=1, n_init=10)
cluster_label = kmeans.fit_predict(x)   # <-- this creates the 'labels' array

# 3. Reduce to 2D for visualization
pca = PCA(n_components=2)
X_2d = pca.fit_transform(x)

# 4. Plot clusters
plt.figure(figsize=(6,5))
plt.scatter(X_2d[:,0], X_2d[:,1], c=cluster_label, cmap='coolwarm', s=30, alpha=0.8)
plt.xlabel("PCA 1")
plt.ylabel("PCA 2")
plt.title("Visualization of 2 Clusters")
plt.show()
# after scaling
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans

# 1. Scale the data
scaler = StandardScaler()
X_scaled = scaler.fit_transform(x)

# 2. Run KMeans with 2 clusters
kmeans = KMeans(n_clusters=2, random_state=1, n_init=10)
cluster_label = kmeans.fit_predict(X_scaled)   # <-- this creates the 'labels' array

# 3. Reduce to 2D for visualization
pca = PCA(n_components=2)
X_2d = pca.fit_transform(X_scaled)

# 4. Plot clusters
plt.figure(figsize=(6,5))
plt.scatter(X_2d[:,0], X_2d[:,1], c=cluster_label, cmap='coolwarm', s=30, alpha=0.8)
plt.xlabel("PCA 1")
plt.ylabel("PCA 2")
plt.title("Visualization of 2 Clusters")
plt.show()
#mapping their behavior pattern to give them a categorization and adding it into the dataframe

label_map = {0: 'cluster_1', 1: 'cluster_2'}
dataset_kmeans['kmeans_cluster'] = dataset_kmeans['kmeans_cluster'].map(label_map)
display(dataset_kmeans.head(10))
dataset_kmeans['kmeans_cluster'].value_counts()
import matplotlib.pyplot as plt

plt.figure(figsize=(6,4))
plt.bar(accuracy.keys(), accuracy.values(), color="skyblue")

plt.ylabel("Accuracy")
plt.title("Model Accuracy Comparison")
plt.ylim(0, 1)  # since accuracy is between 0 and 1

# add text labels on bars
for i, (model, acc) in enumerate(accuracy.items()):
    plt.text(i, acc + 0.01, f"{acc:.2f}", ha="center")

plt.show()
from sklearn.metrics import precision_score, recall_score
y_true = y_test

precisions = {}
recalls = {}

#knn
y_pred_knn = knn.predict(X_test)
precisions["knn"] = precision_score(y_true, y_pred_knn, average="macro")
recalls["knn"]    = recall_score(y_true, y_pred_knn, average="macro")

#logreg
y_pred_log = log_reg.predict(X_test)
precisions["logreg"] = precision_score(y_true, y_pred_log, average="macro")
recalls["logreg"]    = recall_score(y_true, y_pred_log, average="macro")

# mlp (nn)
y_pred_nn = mlp.predict(X_test)
precisions["nn"] = precision_score(y_true, y_pred_nn, average="macro")
recalls["nn"]    = recall_score(y_true, y_pred_nn, average="macro")

# dt
y_pred_dt = dt.predict(X_test)
precisions["dt"] = precision_score(y_true, y_pred_dt, average="macro")
recalls["dt"]    = recall_score(y_true, y_pred_dt, average="macro")

#Plot Precision
plt.figure(figsize=(6,4))
plt.bar(precisions.keys(), precisions.values(), color="lightgreen")
plt.ylabel("Precision")
plt.title("Model Precision Comparison")
plt.ylim(0,1)
for i, (model, prec) in enumerate(precisions.items()):
    plt.text(i, prec + 0.01, f"{prec:.2f}", ha="center")
plt.show()

#Plot Recall
plt.figure(figsize=(6,4))
plt.bar(recalls.keys(), recalls.values(), color="orange")
plt.ylabel("Recall")
plt.title("Model Recall Comparison")
plt.ylim(0,1)
for i, (model, rec) in enumerate(recalls.items()):
    plt.text(i, rec + 0.01, f"{rec:.2f}", ha="center")
plt.show()

from sklearn.metrics import confusion_matrix
import seaborn as sns

models = {
    "KNN": knn,
    "Logistic Regression": log_reg,
    "Neural Network": mlp,
    "Decision Tree": dt
}

for name, model in models.items():
    y_pred = model.predict(X_test_scaled) # over scaled obvi
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)

    # Plot
    plt.figure(figsize=(2,2))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", cbar=False)
    plt.title(f"Confusion Matrix - {name}")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.show()
from sklearn.metrics import roc_curve, roc_auc_score
import matplotlib.pyplot as plt

models = {
    "KNN": knn,
    "Logistic Regression": log_reg,
    "Neural Net": mlp,
    "Decision Tree": dt
}

plt.figure(figsize=(7,6))

for name, model in models.items():
    # check if model can output probabilities
    if hasattr(model, "predict_proba"):
        y_score = model.predict_proba(X_test)[:,1]   # prob for cls1
    else:
        y_score = model.decision_function(X_test)    # fallback

    # ROC curve
    fpr, tpr, _ = roc_curve(y_test, y_score)
    auc_score = roc_auc_score(y_test, y_score)

    plt.plot(fpr, tpr, label=f"{name} (AUC = {auc_score:.2f})")

# reference line (random guess)
plt.plot([0,1], [0,1], "k--")

plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("ROC Curves for Models")
plt.legend()
plt.show()
from sklearn.metrics import roc_auc_score
import matplotlib.pyplot as plt

models = {
    "knn": knn,
    "logreg": log_reg,
    "nn": mlp,
    "dt": dt,
}

# compute AUCs (binary: uses class-1 scores)
aucs = {}
for name, model in models.items():
    if hasattr(model, "predict_proba"):
        y_score = model.predict_proba(X_test)[:, 1]
    else:
        y_score = model.decision_function(X_test)
    aucs[name] = roc_auc_score(y_test, y_score)

# bar chart
plt.figure(figsize=(6,4))
plt.bar(aucs.keys(), aucs.values())
plt.ylabel("AUC")
plt.title("Model AUC Comparison")
plt.ylim(0, 1)
for i, (model, aucv) in enumerate(aucs.items()):
    plt.text(i, aucv + 0.01, f"{aucv:.2f}", ha="center")
plt.show()