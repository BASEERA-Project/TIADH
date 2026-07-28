import streamlit as st
import pandas as pd
import json
import plotly.express as px

from db.database import Database 

st.set_page_config(page_title="TIADH Dashboard", layout="wide", page_icon="🛡️")
st.title("TIADH Dashboard")

@st.cache_resource
def get_db():
    return Database(read_only=True)

db = get_db()

df = pd.DataFrame(db.get_sessions())

if not df.empty:
    total_attacks = len(df[df['event_type'] != 'heartbeat']) 
    login_attempts = len(df[df['event_type'] == 'login_attempt'])
    unique_ips = df[df['event_type'] != 'heartbeat']['attacker_ip'].nunique()

    col1, col2, col3 = st.columns(3)
    col1.metric("🚨 Total Attacks", total_attacks)
    col2.metric("🔑 Total Login Attempts", login_attempts)
    col3.metric("🌐 Unique Attacker IPs", unique_ips)

    st.divider()

    col_left, col_right = st.columns(2, gap="large")

    with col_left:
        st.subheader("🎯 Top Attacking IPs")
        attack_events = df[df['event_type'] != 'heartbeat']
        
        if not attack_events.empty:
            top_ips = attack_events['attacker_ip'].value_counts().reset_index().head(10)
            top_ips.columns = ['Attacker IP', 'Count']
            
            fig_ips = px.bar(top_ips, y='Count', x='Attacker IP')
            fig_ips.update_layout(yaxis={'categoryorder':'total ascending'})
            st.plotly_chart(fig_ips, width='stretch')
        else:
            st.info("No attacker IPs logged yet.")

    with col_right:
        st.subheader("💻 Top Executed Commands")
        command_events = df[df['event_type'] == 'command'].copy()
        
        if not command_events.empty:
            command_events['parsed_command'] = command_events['details'].apply(
                lambda x: json.loads(x).get('command') if pd.notnull(x) else None
            )
            top_commands = command_events['parsed_command'].value_counts().reset_index().head(10)
            top_commands.columns = ['Command', 'Count']

            # Upgrade to an interactive Plotly chart for commands
            fig_cmds = px.bar(top_commands, y='Count', x='Command')
            fig_cmds.update_layout(yaxis={'categoryorder':'total ascending'})
            st.plotly_chart(fig_cmds, width='stretch')
        else:
            st.info("No commands logged yet.")
else:
    st.warning("No events found in the database.")
    