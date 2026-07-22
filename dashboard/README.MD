# Dashboard
This is a simple dashboard built for TIADH project.
## Configurations
Before running the dashboard, rename the file `template.secerets.toml` (found in `.streamlit` folder) to `secrets.toml` and set the path of the SQLite database.
## Usage
1. Setup a python virtual environment:
```
python -m venv .venv
```
2. Activate virtual environment:
```
.venv\Scripts\activate.bat
```
3. Install dependencies:
```
pip install -r requirements.txt
```
4. Run streamlit app:
```
streamlit run app.py
```
To deactivate venv session run this command:
```
deactivate
```