import streamlit as st
from agents.security_agent import SecurityAgent
from core.scope import ScopeDefinition
from loguru import logger

def main():
    st.title("Cybersecurity Audit Assistant")

    # Scope Definition
    st.header("Define Scope")
    domains = st.text_area("Target Domains (one per line)", "example.com")
    ip_ranges = st.text_area("IP Ranges (one per line)", "192.168.1.0/24")
    wildcards = st.text_area("Wildcard Domains (one per line)", "*.example.com")

    # Create scope
    scope = ScopeDefinition(
        domains=domains.split("\n"),
        ip_ranges=ip_ranges.split("\n"),
        wildcards=wildcards.split("\n")
    )

    # Security instruction
    instruction = st.text_area(
        "Security Instruction",
        "Scan example.com for open ports and discover directories"
    )

    if st.button("Start Scan"):
        agent = SecurityAgent(scope)
        
        # Create a progress container
        progress_container = st.empty()
        
        try:
            with st.spinner("Running security scan..."):
                result = agent.run(instruction)
                
                # Display results
                st.success("Scan completed!")
                st.json(result)
        except Exception as e:
            st.error(f"Scan failed: {str(e)}")

if __name__ == "__main__":
    main()