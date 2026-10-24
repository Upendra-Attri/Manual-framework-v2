import streamlit as st

from modules.gui_functions import db_admin_ui


st.set_page_config(page_title="Manual Framework DB Manager", layout="wide")
db_admin_ui()
