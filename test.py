import time
import random
import re
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM, pipeline
import torch

# Check if CUDA is available and set the device
device = 0 if torch.cuda.is_available() else -1

# Set up the text generation pipeline with BART
model_name = "facebook/bart-large-cnn"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSeq2SeqLM.from_pretrained(model_name)
generator = pipeline('summarization', model=model, tokenizer=tokenizer, device=device)

def simulate_anomaly_detection(log_entry):
    # Simulate more realistic anomaly scores based on log content
    if "failed login attempts" in log_entry.lower():
        return random.uniform(0.7, 1.0)
    elif "unusual" in log_entry.lower():
        return random.uniform(0.6, 0.9)
    elif "admin" in log_entry.lower():
        return random.uniform(0.5, 0.8)
    else:
        return random.uniform(0.1, 0.5)

def extract_datetime(log_entry):
    datetime_match = re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', log_entry)
    return datetime_match.group() if datetime_match else "Date and time not found in log"

def generate_analysis(log_entry, anomaly_score):
    prompt = f"""
As a cybersecurity expert, analyze the following log entry:
Log: {log_entry}
Anomaly Score: {anomaly_score:.2f}

Please provide a detailed analysis including:
1. Event classification and potential attack type
2. Potential security implications
3. Possible attack vectors or causes
4. Immediate actions to be taken
5. Severity (Low/Medium/High/Critical) and potential impact

Provide clear and actionable insights.
"""

    response = generator(prompt, max_length=300, min_length=100, num_return_sequences=1, temperature=0.7)
    analysis = response[0]['summary_text'].strip()
    
    # Ensure the log entry is included in the analysis
    analysis = f"Log Entry: {log_entry}\n\nAnalysis:\n{analysis}"
    return analysis

def generate_report(log_entry, anomaly_score):
    log_datetime = extract_datetime(log_entry)
    analysis = generate_analysis(log_entry, anomaly_score)
    
    # Extract the event type from the analysis
    event_type_match = re.search(r"Event classification:?\s*([^\n.]+)", analysis)
    event_type = event_type_match.group(1) if event_type_match else "Unclassified Event"
    
    report = f"""
Alert Title: Potential Security Event Detected
Date and Time: {log_datetime}
Event Description: {log_entry}
Anomaly Score: {anomaly_score:.2f}
Event Type: {event_type}

{analysis}
"""
    return report

def analyze_log(log_entry):
    start_time = time.time()
    anomaly_score = simulate_anomaly_detection(log_entry)
    report = generate_report(log_entry, anomaly_score)
    end_time = time.time()
    processing_time = end_time - start_time
    return report, anomaly_score, processing_time

if __name__ == "__main__":
    log_entries = [
        "2024-07-18 14:30:00 - Multiple failed login attempts from IP 192.168.1.100 in the last 5 minutes.",
        "2024-07-18 15:45:23 - User 'admin' logged in successfully from IP 10.0.0.1.",
        "2024-07-18 16:20:15 - Unusual outbound traffic spike detected on port 443.",
        "2024-07-18 17:00:00 - System update completed successfully."
    ]
    
    alerts = []
    total_anomaly_score = 0
    total_processing_time = 0
    
    for entry in log_entries:
        report, anomaly_score, proc_time = analyze_log(entry)
        total_processing_time += proc_time
        total_anomaly_score += anomaly_score
        
        if anomaly_score > 0.5:  # Adjust this threshold as needed
            alerts.append(report)
            print(report)
            print(f"Processing time: {proc_time:.2f} seconds\n")
            print("-" * 50)
    
    print("\nOverview of Log Analysis:")
    print(f"Total log entries processed: {len(log_entries)}")
    print(f"Number of alerts generated: {len(alerts)}")
    print(f"Average anomaly score: {total_anomaly_score / len(log_entries):.2f}")
    print(f"Total processing time: {total_processing_time:.2f} seconds")
    print(f"Average processing time per log: {total_processing_time / len(log_entries):.2f} seconds")