import tkinter as tk
from tkinter import filedialog, StringVar, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.scrolled import ScrolledText
from ttkbootstrap.dialogs import Messagebox
from PIL import Image, ImageTk
import time
import threading
import os
import re
import json
import numpy as np
import pandas as pd
import email
from email import policy
from email.parser import BytesParser, Parser
import joblib
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import urllib.parse
import hashlib
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from pathlib import Path
import csv
import webbrowser
import traceback


class PhishingDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Email Detector")
        self.root.geometry("1000x700")
        self.style = ttk.Style("darkly")  # Modern dark theme

        # Initialize data structures
        self.suspicious_urls = []
        self.analysis_results = None
        self.current_email = None
        self.features_dict = {}
        self.loaded_model = None
        self.model_metadata = {}

        # Define file paths
        self.app_dir = os.path.dirname(os.path.abspath(__file__))
        self.data_dir = os.path.join(self.app_dir, "data")
        self.urls_file = os.path.join(self.data_dir, "suspicious_urls.json")
        self.models_dir = os.path.join(self.app_dir, "models")
        self.history_file = os.path.join(self.data_dir, "analysis_history.json")

        # Ensure directories exist
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.models_dir, exist_ok=True)

        # Current user and datetime (updated)
        self.current_user = "وزير الشباب والرياضة البشمهندس و دكتور القسم مستقبلا (رامي عبيد) "
        self.current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Load suspicious URLs from file
        self.load_suspicious_urls()

        # Store the root to hide it during splash screen
        self.root.withdraw()

        # Launch splash screen
        self.show_splash()


    def show_splash(self):
        """Display welcome splash screen with animation"""
        # Create splash window
        self.splash = tk.Toplevel(self.root)
        self.splash.title("")
        self.splash.geometry("600x400")
        self.splash.overrideredirect(True)  # No window decorations
        self.splash.configure(bg="#1a1a1a")

        # Center the splash screen
        screen_width = self.splash.winfo_screenwidth()
        screen_height = self.splash.winfo_screenheight()
        x = (screen_width - 600) // 2
        y = (screen_height - 400) // 2
        self.splash.geometry(f"600x400+{x}+{y}")

        # Create a canvas for animations
        canvas = tk.Canvas(self.splash, bg="#1a1a1a", highlightthickness=0)
        canvas.pack(fill=tk.BOTH, expand=True)

        # Logo/icon
        logo_frame = ttk.Frame(canvas, bootstyle="dark")
        logo_frame.place(relx=0.5, rely=0.35, anchor=tk.CENTER)

        shield_icon = ttk.Label(
            logo_frame,
            text="🛡️",
            font=("Segoe UI", 60),
            bootstyle="light"
        )
        shield_icon.pack()

        # App name
        title_label = ttk.Label(
            canvas,
            text="PHISHING DETECTOR",
            font=("Segoe UI", 24, "bold"),
            bootstyle="light"
        )
        title_label.place(relx=0.5, rely=0.55, anchor=tk.CENTER)

        # Tagline
        tagline_label = ttk.Label(
            canvas,
            text="Advanced email security with machine learning",
            font=("Segoe UI", 12),
            bootstyle="secondary"
        )
        tagline_label.place(relx=0.5, rely=0.65, anchor=tk.CENTER)

        # Progress bar
        self.progress = ttk.Progressbar(
            canvas,
            length=400,
            mode="determinate",
            bootstyle="success-striped"
        )
        self.progress.place(relx=0.5, rely=0.8, anchor=tk.CENTER, width=400)

        # Version and copyright
        version_label = ttk.Label(
            canvas,
            text=f"v1.0.0 • {self.current_datetime}",
            font=("Segoe UI", 8),
            bootstyle="secondary"
        )
        version_label.place(relx=0.5, rely=0.9, anchor=tk.CENTER)

        # Start loading animation
        self.simulate_loading()

    def simulate_loading(self):
        """Simulate loading progress with animation"""

        def update_progress():
            try:
                for i in range(101):
                    time.sleep(0.02)  # Faster loading for demo
                    self.progress["value"] = i

                    # Train custom model at 50%
                    if i == 50:
                        self.train_custom_model()

                    # Update splash screen
                    if i == 100:
                        time.sleep(0.5)  # Pause at 100%
                        if self.splash.winfo_exists():
                            self.splash.destroy()
                        self.root.deiconify()  # Show main window
                        self.setup_main_ui()  # Setup main UI components
            except Exception as e:
                print(f"Error in loading: {e}")
                traceback.print_exc()
                # Ensure we show the main window even if there's an error
                if hasattr(self, 'splash') and self.splash.winfo_exists():
                    self.splash.destroy()
                self.root.deiconify()
                self.setup_main_ui()

        # Start progress in a separate thread to keep UI responsive
        threading.Thread(target=update_progress, daemon=True).start()

    def train_custom_model(self):
        """Train a custom phishing detection model using the specified datasets"""
        try:
            self.update_status("Training custom model...", "info")

            # Define dataset paths
            dataset_paths = [
                r"C:\Users\DELL\PycharmProjects\PythonProject1\CEAS_08.csv",
                r"C:\Users\DELL\PycharmProjects\PythonProject1\Nigerian_Fraud.csv",
                r"C:\Users\DELL\PycharmProjects\PythonProject1\Nazario.csv"
            ]

            # Initialize empty datasets
            all_data = []
            all_labels = []

            # Load and process each dataset
            for dataset_path in dataset_paths:
                try:
                    print(f"Processing dataset: {os.path.basename(dataset_path)}")

                    # Load CSV file with proper settings to handle mixed data types
                    df = pd.read_csv(dataset_path, encoding='latin1', on_bad_lines='skip', low_memory=False)

                    # Check which columns exist
                    headers = df.columns.tolist()

                    # Extract email text depending on available columns
                    text_column = None
                    for possible_column in ['body', 'content', 'text', 'email', 'message']:
                        if possible_column in headers:
                            text_column = possible_column
                            break

                    if text_column is None:
                        # Use first string column found
                        text_columns = [col for col in headers if df[col].dtype == 'object']
                        if text_columns:
                            text_column = text_columns[0]
                        else:
                            print(f"No text column found in {dataset_path}")
                            continue

                    # Get the text data
                    texts = df[text_column].fillna('').astype(str)

                    # Extract label depending on available columns
                    label_column = None
                    for possible_column in ['label', 'is_phishing', 'phishing', 'class', 'spam', 'is_spam']:
                        if possible_column in headers:
                            label_column = possible_column
                            break

                    if label_column is None:
                        # Use filename to determine labels (assuming Nigerian_Fraud and Nazario are phishing)
                        if 'Nigerian_Fraud' in dataset_path or 'Nazario' in dataset_path:
                            labels = pd.Series([1] * len(texts))  # All phishing
                        else:
                            # Try to find binary column
                            binary_cols = [col for col in headers if
                                           set(pd.unique(df[col].dropna())) <= {0, 1, 0.0, 1.0}]
                            if binary_cols:
                                label_column = binary_cols[0]
                                labels = df[label_column]
                            else:
                                print(f"No label column found in {dataset_path}")
                                continue
                    else:
                        labels = df[label_column]

                    # Process each sample
                    processed_count = 0
                    for i, (text, label) in enumerate(zip(texts, labels)):
                        try:
                            # Skip NaN values
                            if pd.isna(label):
                                continue

                            # Skip empty texts
                            if not text or pd.isna(text) or len(str(text).strip()) == 0:
                                continue

                            # Extract features
                            features = self.extract_features_from_text(text)

                            # Skip if feature extraction failed (returned None)
                            if features is None:
                                continue

                            all_data.append(features)
                            all_labels.append(
                                int(float(label)))  # Convert to int through float to handle '1.0' type values
                            processed_count += 1

                        except Exception as e:
                            # Print error but continue with next sample
                            print(f"Error processing sample {i} from {os.path.basename(dataset_path)}: {e}")
                            continue

                    print(f"Processed {processed_count} valid emails from {os.path.basename(dataset_path)}")

                except Exception as e:
                    print(f"Error processing dataset {dataset_path}: {e}")
                    traceback.print_exc()

            # Check if we have enough data
            if len(all_data) < 10:
                print("Not enough data to train model")
                self.create_default_model(os.path.join(self.models_dir, "phishing_detector_model.joblib"))
                return

            # Ensure consistent data lengths
            print(f"Raw data: {len(all_data)} samples, {len(all_labels)} labels")

            if len(all_data) != len(all_labels):
                print(f"Warning: Inconsistent data length. Features: {len(all_data)}, Labels: {len(all_labels)}")
                # Take the minimum length to ensure consistency
                min_len = min(len(all_data), len(all_labels))
                all_data = all_data[:min_len]
                all_labels = all_labels[:min_len]

            # Convert to numpy arrays
            X = np.array(all_data)
            y = np.array(all_labels)

            print(f"Final dataset size: {len(X)} samples with {X.shape[1]} features")

            # Train a Random Forest model
            model = RandomForestClassifier(n_estimators=100, random_state=42)
            model.fit(X, y)

            # Save the model
            os.makedirs(self.models_dir, exist_ok=True)
            model_path = os.path.join(self.models_dir, "phishing_detector_model.joblib")
            joblib.dump(model, model_path)

            # Save model metadata
            self.model_metadata = {
                "model_type": "Random Forest Classifier",
                "version": "1.0.0",
                "last_updated": self.current_datetime,
                "features_used": X.shape[1],
                "training_data_size": len(X),
                "dataset_files": [os.path.basename(path) for path in dataset_paths],
                "accuracy": "N/A (no validation performed)",
                "created_by": self.current_user
            }

            metadata_path = os.path.join(self.models_dir, "model_metadata.json")
            with open(metadata_path, 'w') as file:
                json.dump(self.model_metadata, file, indent=2)

            # Set the model
            self.loaded_model = model
            self.model_feature_count = X.shape[1]
            self.update_status("Custom model trained successfully", "success")

        except Exception as e:
            print(f"Error training custom model: {e}")
            traceback.print_exc()
            self.create_default_model(os.path.join(self.models_dir, "phishing_detector_model.joblib"))

    def extract_features_from_text(self, text):
        """Extract standardized features from email text for model training"""
        try:
            # Initialize features array
            features = np.zeros(10)  # Using 10 features for comprehensive analysis

            # Convert text to lowercase for case-insensitive matching
            text = str(text).lower()

            # Feature 1: Contains suspicious sender patterns (from, paypal, bank, etc.)
            suspicious_senders = ['paypal', 'bank', 'account', 'security', 'update', 'verify', 'amazon']
            features[0] = int(any(sender in text[:500] for sender in suspicious_senders))

            # Feature 2: Contains URLs
            features[1] = int(bool(re.search(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', text)))

            # Feature 3: Contains shortened URLs
            short_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
            features[2] = int(any(domain in text for domain in short_domains))

            # Feature 4: Contains IP-based URLs
            features[3] = int(bool(re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text)))

            # Feature 5: Contains urgency words
            urgency_words = ['urgent', 'immediately', 'alert', 'verify', 'suspend', 'restrict',
                             'limited', 'expires', 'validate', 'confirm']
            features[4] = int(any(word in text for word in urgency_words))

            # Feature 6: Contains sensitive data requests
            sensitive_requests = ['password', 'credit card', 'ssn', 'social security', 'credentials',
                                  'login', 'username', 'pin', 'bank account', 'billing']
            features[5] = int(any(req in text for req in sensitive_requests))

            # Feature 7: Contains suspicious attachment mentions
            attachment_words = ['attach', 'document', 'file', 'pdf', 'doc', 'invoice', 'receipt', 'statement']
            features[6] = int(any(word in text for word in attachment_words))

            # Feature 8: Contains financial/money terms
            money_terms = ['$', 'dollar', 'payment', 'transfer', 'transaction', 'wire', 'money',
                           'credit', 'debit', 'cash', 'fund', 'tax', 'refund']
            features[7] = int(any(term in text for term in money_terms))

            # Feature 9: Contains threatening language
            threat_terms = ['suspended', 'terminated', 'unauthorized', 'closed', 'limited',
                            'suspicious activity', 'unusual', 'breach', 'compromised', 'fraud']
            features[8] = int(any(term in text for term in threat_terms))

            # Feature 10: Contains suspicious offers/claims
            offer_terms = ['won', 'winner', 'prize', 'million', 'free', 'discount', 'offer',
                           'reward', 'gift', 'claim', 'congratulations', 'selected']
            features[9] = int(any(term in text for term in offer_terms))

            return features
        except Exception as e:
            print(f"Error extracting features: {e}")
            # Return zeros if extraction fails to maintain consistency
            return np.zeros(10)


    def create_default_model(self, model_path):
        """Create a simple default model if none exists"""
        try:
            # Create a simple RandomForest model
            model = RandomForestClassifier(n_estimators=100, random_state=42)

            # Create sample data to fit the model (minimal just to initialize)
            # Use our feature count (10 features)
            X = np.array([[0] * 10, [1] * 10])
            y = np.array([0, 1])

            # Fit and save the model
            model.fit(X, y)
            joblib.dump(model, model_path)

            self.loaded_model = model
            self.model_feature_count = 10  # Default model uses 10 features
            print(f"Created default model at: {model_path}")
        except Exception as e:
            print(f"Error creating default model: {e}")
            traceback.print_exc()

    def setup_main_ui(self):
        """Set up the main application UI after splash screen"""
        try:
            # Create header with app title and user info
            self.create_header()

            # Create a notebook for tabs
            self.tab_control = ttk.Notebook(self.root)

            # Create the tabs
            self.analyze_tab = ttk.Frame(self.tab_control)
            self.report_tab = ttk.Frame(self.tab_control)
            self.urls_tab = ttk.Frame(self.tab_control)
            self.settings_tab = ttk.Frame(self.tab_control)

            # Add tabs to notebook with icons
            self.tab_control.add(self.analyze_tab, text="✉️ Analyze Email")
            self.tab_control.add(self.report_tab, text="📊 Report")
            self.tab_control.add(self.urls_tab, text="🔗 Suspicious URLs")
            self.tab_control.add(self.settings_tab, text="⚙️ Model/Settings")
            self.tab_control.pack(expand=1, fill="both", padx=10, pady=(10, 0))

            # Setup each tab
            self.setup_analyze_tab()
            self.setup_report_tab()
            self.setup_urls_tab()
            self.setup_settings_tab()

            # Footer status bar
            self.create_footer()
        except Exception as e:
            print(f"Error setting up UI: {e}")
            traceback.print_exc()

    def create_header(self):
        """Create app header with title and user info"""
        header_frame = ttk.Frame(self.root, bootstyle="dark")
        header_frame.pack(fill=tk.X, padx=0, pady=0)

        # Left side - App title
        title_frame = ttk.Frame(header_frame, bootstyle="dark")
        title_frame.pack(side=tk.LEFT, padx=15, pady=10)

        # App icon and title
        title_label = ttk.Label(
            title_frame,
            text="🛡️ Phishing Detector",
            font=("Segoe UI", 16, "bold"),
            bootstyle="light"
        )
        title_label.pack(side=tk.LEFT)

        # Right side - User info
        user_frame = ttk.Frame(header_frame, bootstyle="dark")
        user_frame.pack(side=tk.RIGHT, padx=15, pady=10)

        # User avatar (placeholder circle)
        user_avatar = ttk.Label(
            user_frame,
            text="👤",  # Placeholder avatar
            font=("Segoe UI", 14),
            bootstyle="light"
        )
        user_avatar.pack(side=tk.LEFT, padx=(0, 5))

        # User name
        user_label = ttk.Label(
            user_frame,
            text=f"Welcome, {self.current_user}",
            font=("Segoe UI", 10),
            bootstyle="light"
        )
        user_label.pack(side=tk.LEFT)

    def create_footer(self):
        """Create footer with status information"""
        self.footer_frame = ttk.Frame(self.root, bootstyle="dark")
        self.footer_frame.pack(side=tk.BOTTOM, fill=tk.X)

        # Status indicator - green dot for "ready"
        self.status_text_indicator = ttk.Label(
            self.footer_frame,
            text="●",
            font=("Segoe UI", 14),
            foreground="#28a745"
        )
        self.status_text_indicator.pack(side=tk.LEFT, padx=10, pady=5)

        # Status text
        self.status_text = ttk.Label(
            self.footer_frame,
            text="Ready",
            bootstyle="light"
        )
        self.status_text.pack(side=tk.LEFT, padx=0, pady=5)

        # Date/time on right
        self.datetime_label = ttk.Label(
            self.footer_frame,
            text=f"Last updated: {self.current_datetime}",
            bootstyle="secondary"
        )
        self.datetime_label.pack(side=tk.RIGHT, padx=10, pady=5)

    def update_status(self, message, status_type="success"):
        """Update the status bar with a message and appropriate color - Thread Safe"""

        def _update():
            color_map = {
                "success": "#28a745",
                "warning": "#ffc107",
                "error": "#dc3545",
                "info": "#17a2b8"
            }

            if hasattr(self, 'status_text_indicator'):
                self.status_text_indicator.config(foreground=color_map.get(status_type, "#28a745"))
            if hasattr(self, 'status_text'):
                self.status_text.config(text=message)
            if hasattr(self, 'datetime_label'):
                self.datetime_label.config(text=f"Last updated: {self.current_datetime}")

        # Check if we're in the main thread
        if threading.current_thread() is threading.main_thread():
            _update()
        else:
            # Schedule the update to run in the main thread
            self.root.after(0, _update)

    def setup_analyze_tab(self):
        """Set up the analyze email tab with modern UI components"""
        # Container with padding
        container = ttk.Frame(self.analyze_tab)
        container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # Left panel - Email input
        left_panel = ttk.Frame(container)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Right panel - Controls and info
        # Set width when creating the frame, not when packing it
        right_panel = ttk.Frame(container, width=250)
        right_panel.pack_propagate(False)  # Prevents the frame from shrinking to fit contents
        right_panel.pack(side=tk.RIGHT, fill=tk.Y, padx=(15, 0))  # Width removed from here

        # Email input area with title
        input_label = ttk.Label(
            left_panel,
            text="Email Content",
            font=("Segoe UI", 14, "bold")
        )
        input_label.pack(anchor=tk.W, pady=(0, 10))

        # Email text area with line numbers and syntax highlighting
        self.email_text = ScrolledText(
            left_panel,
            height=20,
            autohide=True,
            bootstyle="info"
        )
        self.email_text.pack(fill=tk.BOTH, expand=True)

        # Placeholder text
        placeholder = "Paste the email content here or upload an .eml file...\n\n" \
                      "You can paste the raw email including headers, or just the message body.\n" \
                      "For best results, include as much of the original email as possible."
        self.email_text.insert(tk.END, placeholder)

        # Right panel components
        # 1. File Upload Section
        upload_frame = ttk.LabelFrame(
            right_panel,
            text="Upload Email",
            bootstyle="info"
        )
        upload_frame.pack(fill=tk.X, pady=(0, 15))

        upload_btn = ttk.Button(
            upload_frame,
            text="Upload .eml File",
            command=self.upload_eml_file,
            bootstyle="info-outline"
        )
        upload_btn.pack(padx=10, pady=10)

        # 2. Model Selection
        model_frame = ttk.LabelFrame(
            right_panel,
            text="Model Selection",
            bootstyle="info"
        )
        model_frame.pack(fill=tk.X, pady=(0, 15))

        # Model type radio buttons
        self.model_type = StringVar(value="existing")

        existing_radio = ttk.Radiobutton(
            model_frame,
            text="Use existing model",
            variable=self.model_type,
            value="existing",
            command=self.toggle_model_selection,
            bootstyle="info"
        )
        existing_radio.pack(fill=tk.X, padx=10, pady=(10, 5), anchor=tk.W)

        external_radio = ttk.Radiobutton(
            model_frame,
            text="Train new model",
            variable=self.model_type,
            value="external",
            command=self.toggle_model_selection,
            bootstyle="info"
        )
        external_radio.pack(fill=tk.X, padx=10, pady=(0, 5), anchor=tk.W)

        # Model info
        ttk.Label(model_frame, text="Current Model:").pack(anchor=tk.W, padx=10, pady=(5, 0))

        self.model_info_label = ttk.Label(
            model_frame,
            text="Custom Trained Model" if self.loaded_model else "No model loaded",
            bootstyle="info",
            wraplength=220
        )
        self.model_info_label.pack(padx=10, pady=(5, 10), fill=tk.X)

        # External model path display
        self.external_model_frame = ttk.Frame(model_frame)
        self.external_model_label = ttk.Label(
            self.external_model_frame,
            text="Train with custom datasets",
            bootstyle="secondary",
            wraplength=200
        )
        self.external_model_label.pack(padx=10, pady=5, fill=tk.X)

        # Initially hide the external model frame
        # Will be shown when "Train new model" is selected

        # 3. Analyze Button
        self.analyze_btn = ttk.Button(
            right_panel,
            text="Analyze Email",
            command=self.analyze_email,
            bootstyle="success"
        )
        self.analyze_btn.pack(fill=tk.X, pady=(0, 15))

        # 4. Quick Info Panel
        info_frame = ttk.LabelFrame(
            right_panel,
            text="Analysis Information",
            bootstyle="info"
        )
        info_frame.pack(fill=tk.BOTH, expand=True)

        # Status indicator
        status_frame = ttk.Frame(info_frame)
        status_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(
            status_frame,
            text="Status:",
            font=("Segoe UI", 10, "bold")
        ).pack(side=tk.LEFT)

        self.analysis_status_label = ttk.Label(
            status_frame,
            text="Ready to analyze",
            bootstyle="success"
        )
        self.analysis_status_label.pack(side=tk.LEFT, padx=(5, 0))

        # Previous results
        ttk.Separator(info_frame).pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(
            info_frame,
            text="Recent Analyses:",
            font=("Segoe UI", 10, "bold")
        ).pack(anchor=tk.W, padx=10, pady=(5, 0))

        # Create a frame for previous results that will be updated
        self.prev_results_frame = ttk.Frame(info_frame)
        self.prev_results_frame.pack(fill=tk.X, padx=10, pady=5)

        # Load and display previous analysis history
        self.load_analysis_history()

    def setup_report_tab(self):
        """Set up the report tab with a placeholder for analysis results"""
        container = ttk.Frame(self.report_tab)
        container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # Initial message when no analysis has been performed
        self.report_placeholder = ttk.Label(
            container,
            text="No analysis results yet. Please analyze an email first.",
            font=("Segoe UI", 12),
            bootstyle="secondary"
        )
        self.report_placeholder.pack(expand=True)

    def setup_urls_tab(self):
        """Set up the tab for displaying and managing suspicious URLs"""
        container = ttk.Frame(self.urls_tab)
        container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # Title and description
        title_frame = ttk.Frame(container)
        title_frame.pack(fill=tk.X, pady=(0, 15))

        ttk.Label(
            title_frame,
            text="Suspicious URL Database",
            font=("Segoe UI", 16, "bold")
        ).pack(side=tk.LEFT)

        # Control buttons
        control_frame = ttk.Frame(container)
        control_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Button(
            control_frame,
            text="Add URL",
            command=self.add_url_dialog,
            bootstyle="info-outline"
        ).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(
            control_frame,
            text="Remove Selected",
            command=self.remove_selected_url,
            bootstyle="danger-outline"
        ).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(
            control_frame,
            text="Export List",
            command=self.export_urls,
            bootstyle="secondary-outline"
        ).pack(side=tk.LEFT)

        # URL list with scrollbar
        list_frame = ttk.Frame(container)
        list_frame.pack(fill=tk.BOTH, expand=True)

        # Column headings
        columns = ("#", "URL", "Source", "Date Added", "Risk Level")
        self.url_tree = ttk.Treeview(
            list_frame,
            columns=columns,
            show="headings",
            bootstyle="info"
        )

        # Configure columns
        self.url_tree.heading("#", text="#")
        self.url_tree.heading("URL", text="URL")
        self.url_tree.heading("Source", text="Source")
        self.url_tree.heading("Date Added", text="Date Added")
        self.url_tree.heading("Risk Level", text="Risk Level")

        self.url_tree.column("#", width=50, anchor="center")
        self.url_tree.column("URL", width=300)
        self.url_tree.column("Source", width=100, anchor="center")
        self.url_tree.column("Date Added", width=150, anchor="center")
        self.url_tree.column("Risk Level", width=100, anchor="center")

        # Add scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.url_tree.yview)
        self.url_tree.configure(yscrollcommand=scrollbar.set)

        # Pack elements
        self.url_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Load and display URLs
        self.display_suspicious_urls()

    def setup_settings_tab(self):
        """Set up the settings tab with model info and app configuration"""
        container = ttk.Frame(self.settings_tab)
        container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # Two-column layout
        left_col = ttk.Frame(container)
        left_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        right_col = ttk.Frame(container)
        right_col.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))

        # Left column - Model Information
        model_frame = ttk.LabelFrame(
            left_col,
            text="Model Information",
            bootstyle="info"
        )
        model_frame.pack(fill=tk.BOTH, expand=True)

        # Model details
        model_details = ttk.Frame(model_frame)
        model_details.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # Model type
        ttk.Label(
            model_details,
            text="Model Type:",
            font=("Segoe UI", 10, "bold")
        ).grid(row=0, column=0, sticky="w", pady=5)

        self.model_type_label = ttk.Label(
            model_details,
            text=self.model_metadata.get("model_type", "Random Forest Classifier")
        )
        self.model_type_label.grid(row=0, column=1, sticky="w", pady=5)

        # Model version
        ttk.Label(
            model_details,
            text="Version:",
            font=("Segoe UI", 10, "bold")
        ).grid(row=1, column=0, sticky="w", pady=5)

        self.model_version_label = ttk.Label(
            model_details,
            text=self.model_metadata.get("version", "1.0.0")
        )
        self.model_version_label.grid(row=1, column=1, sticky="w", pady=5)

        # Last updated
        ttk.Label(
            model_details,
            text="Last Updated:",
            font=("Segoe UI", 10, "bold")
        ).grid(row=2, column=0, sticky="w", pady=5)

        self.model_updated_label = ttk.Label(
            model_details,
            text=self.model_metadata.get("last_updated", self.current_datetime)
        )
        self.model_updated_label.grid(row=2, column=1, sticky="w", pady=5)

        # Features
        ttk.Label(
            model_details,
            text="Features Used:",
            font=("Segoe UI", 10, "bold")
        ).grid(row=3, column=0, sticky="w", pady=5)

        self.model_features_label = ttk.Label(
            model_details,
            text=str(self.model_metadata.get("features_used", 10))  # Default is 10 features
        )
        self.model_features_label.grid(row=3, column=1, sticky="w", pady=5)

        # Training data
        ttk.Label(
            model_details,
            text="Training Data:",
            font=("Segoe UI", 10, "bold")
        ).grid(row=4, column=0, sticky="w", pady=5)

        training_data = self.model_metadata.get("training_data_size", "Custom datasets")
        self.model_training_label = ttk.Label(
            model_details,
            text=str(training_data)
        )
        self.model_training_label.grid(row=4, column=1, sticky="w", pady=5)

        # Dataset files
        ttk.Label(
            model_details,
            text="Datasets:",
            font=("Segoe UI", 10, "bold")
        ).grid(row=5, column=0, sticky="w", pady=5)

        datasets = self.model_metadata.get("dataset_files", ["CEAS_08.csv", "Nigerian_Fraud.csv", "Nazario.csv"])
        datasets_text = "\n".join(datasets) if isinstance(datasets, list) else str(datasets)

        self.model_datasets_label = ttk.Label(
            model_details,
            text=datasets_text,
            wraplength=200
        )
        self.model_datasets_label.grid(row=5, column=1, sticky="w", pady=5)

        # Train new model button
        ttk.Button(
            model_details,
            text="Train New Model",
            command=self.train_custom_model,
            bootstyle="info"
        ).grid(row=6, column=0, columnspan=2, pady=15)

        # Right column - About
        about_frame = ttk.LabelFrame(
            right_col,
            text="About",
            bootstyle="info"
        )
        about_frame.pack(fill=tk.BOTH, expand=True)

        about_content = ttk.Frame(about_frame)
        about_content.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # App logo and name
        ttk.Label(
            about_content,
            text="🛡️",
            font=("Segoe UI", 30)
        ).pack(pady=(0, 5))

        ttk.Label(
            about_content,
            text="Phishing Detector",
            font=("Segoe UI", 14, "bold")
        ).pack(pady=(0, 5))

        ttk.Label(
            about_content,
            text="Version 1.0.0",
            bootstyle="secondary"
        ).pack(pady=(0, 10))

        # Description
        description = "Advanced email security tool that uses machine learning to detect phishing attempts. Analyze emails, track suspicious URLs, and protect yourself from cyber threats."

        desc_label = ttk.Label(
            about_content,
            text=description,
            wraplength=300,
            justify="center"
        )
        desc_label.pack(pady=(0, 10))

        # Links
        links_frame = ttk.Frame(about_content)
        links_frame.pack(pady=(0, 5))

        ttk.Button(
            links_frame,
            text="Documentation",
            command=lambda: webbrowser.open("https://github.com/Sharawey74/phishing-detector"),
            bootstyle="link"
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            links_frame,
            text="Report Issue",
            command=lambda: webbrowser.open("https://github.com/Sharawey74/phishing-detector/issues"),
            bootstyle="link"
        ).pack(side=tk.LEFT, padx=5)

        # Copyright
        ttk.Label(
            about_content,
            text=f"© 2025 {self.current_user}",
            bootstyle="secondary",
            font=("Segoe UI", 8)
        ).pack(pady=(10, 0))

    def toggle_model_selection(self):
        """Toggle between existing model selection and external model loading"""
        if self.model_type.get() == "existing":
            self.external_model_frame.pack_forget()
            self.model_info_label.config(
                text="Using trained model from custom datasets",
                bootstyle="info"
            )
        else:
            self.external_model_frame.pack(fill=tk.X, padx=10, pady=5)
            self.model_info_label.config(
                text="Training new model...",
                bootstyle="warning"
            )
            # Start model training
            self.train_custom_model()

    def get_available_models(self):
        """Get list of available models in the models directory"""
        models = []
        try:
            for file in os.listdir(self.models_dir):
                if file.endswith(('.joblib', '.pkl')) and not file.startswith('._'):
                    models.append(file)

            if not models:
                # Add default model if none found
                models = ["Random Forest (Default)"]
        except Exception as e:
            print(f"Error getting available models: {e}")
            models = ["Random Forest (Default)"]

        return models

    def upload_eml_file(self):
        """Upload and parse .eml file"""
        try:
            file_path = filedialog.askopenfilename(
                title="Select Email File",
                filetypes=[("Email files", "*.eml"), ("Text files", "*.txt"), ("All files", "*.*")]
            )

            if file_path:
                try:
                    # Read the .eml file
                    with open(file_path, 'rb') as file:
                        msg = BytesParser(policy=policy.default).parse(file)

                    # Extract content to display with ALL headers
                    email_content = self.extract_email_content(msg)

                    # Clear and update the text widget
                    self.email_text.delete(1.0, tk.END)
                    self.email_text.insert(tk.END, email_content)

                    # Save the loaded email
                    self.current_email = {
                        'msg': msg,
                        'source': os.path.basename(file_path),
                        'path': file_path
                    }

                    self.update_status(f"Loaded email file: {os.path.basename(file_path)}", "info")
                except Exception as e:
                    print(f"Error loading email: {e}")
                    traceback.print_exc()

                    Messagebox.show_error(
                        f"Error loading email file: {str(e)}",
                        "Error Loading Email"
                    )
                    self.update_status("Error loading email file", "error")
        except Exception as e:
            print(f"Error in upload dialog: {e}")
            traceback.print_exc()

    def extract_email_content(self, msg):
        """Enhanced extraction of content from an email message object with all headers"""
        # Extract all headers
        headers = ""
        for header, value in msg.items():
            headers += f"{header}: {value}\n"
        headers += "\n"

        # Extract body
        body = ""

        # Get plain text content
        if msg.is_multipart():
            for part in msg.iter_parts():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                # Skip attachments
                if "attachment" in content_disposition:
                    continue

                if content_type == "text/plain":
                    try:
                        body += part.get_content()
                    except:
                        body += "Error extracting plain text content"
                    break
        else:
            # Not multipart - get content directly
            content_type = msg.get_content_type()
            if content_type == "text/plain":
                try:
                    body = msg.get_content()
                except:
                    body = "Error extracting plain text content"

        # If we couldn't get plain text, try to get HTML and strip tags
        if not body and msg.is_multipart():
            for part in msg.iter_parts():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                # Skip attachments
                if "attachment" in content_disposition:
                    continue

                if content_type == "text/html":
                    try:
                        # Extract HTML and do basic tag stripping
                        html_content = part.get_content()
                        # Very basic HTML tag removal
                        body = re.sub(r'<[^>]+>', ' ', html_content)
                        body = re.sub(r'\s+', ' ', body).strip()
                    except:
                        body = "Error extracting HTML content"
                    break

        return headers + body

    def analyze_email(self):
        """Analyze the email for phishing indicators"""
        # Get the email content
        email_text = self.email_text.get(1.0, tk.END).strip()

        if not email_text or email_text == "Paste the email content here or upload an .eml file...":
            Messagebox.show_warning(
                "Please enter email content or upload an .eml file.",
                "No Email Content"
            )
            return

        # Store the email content if not already loaded from file
        if not hasattr(self, 'current_email') or self.current_email is None:
            # Parse the email from text
            try:
                msg = Parser(policy=policy.default).parsestr(email_text)
                self.current_email = {
                    'msg': msg,
                    'source': 'manual input',
                    'path': None
                }
            except Exception as e:
                print(f"Error parsing email: {e}")
                traceback.print_exc()
                # If parsing fails, still proceed with the raw text
                self.current_email = {
                    'msg': email_text,
                    'source': 'manual input',
                    'path': None
                }

        # Show loading dialog and start analysis in a separate thread
        self.show_analysis_dialog()

    def show_analysis_dialog(self):
        """Show a loading dialog during email analysis"""
        # Create loading dialog
        loading_window = ttk.Toplevel(self.root)
        loading_window.title("Analyzing Email")
        loading_window.geometry("400x200")

        # Center the loading window
        screen_width = loading_window.winfo_screenwidth()
        screen_height = loading_window.winfo_screenheight()
        x = (screen_width - 400) // 2
        y = (screen_height - 200) // 2
        loading_window.geometry(f"400x200+{x}+{y}")

        # Make it modal
        loading_window.transient(self.root)
        loading_window.grab_set()

        # Loading content
        content_frame = ttk.Frame(loading_window)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        ttk.Label(
            content_frame,
            text="Analyzing Email Content",
            font=("Segoe UI", 14, "bold")
        ).pack(pady=(0, 15))

        # Status message
        status_var = StringVar(value="Extracting email components...")
        status_label = ttk.Label(
            content_frame,
            textvariable=status_var,
            bootstyle="info"
        )
        status_label.pack(pady=(0, 10))

        # Progress bar
        progress = ttk.Progressbar(
            content_frame,
            mode="determinate",
            length=360,
            bootstyle="success-striped"
        )
        progress.pack(pady=(0, 15))

        cancel_button = ttk.Button(
            content_frame,
            text="Cancel",
            command=loading_window.destroy,
            bootstyle="danger-outline"
        )
        cancel_button.pack()

        # Analysis steps
        analysis_steps = [
            "Extracting email components...",
            "Analyzing sender information...",
            "Checking for suspicious URLs...",
            "Scanning for phishing patterns...",
            "Running machine learning model...",
            "Calculating phishing probability...",
            "Generating report..."
        ]

        # Run analysis in a separate thread
        def run_analysis():
            try:
                # Step 1: Extract components
                progress["value"] = 14
                self.root.after(0, lambda: status_var.set(analysis_steps[0]))
                time.sleep(0.5)  # Simulate processing time

                email_features = self.extract_email_features(self.current_email)

                # Step 2: Analyze sender
                progress["value"] = 28
                self.root.after(0, lambda: status_var.set(analysis_steps[1]))
                time.sleep(0.5)

                sender_features = self.analyze_sender(email_features)

                # Step 3: Check URLs
                progress["value"] = 42
                self.root.after(0, lambda: status_var.set(analysis_steps[2]))
                time.sleep(0.5)

                url_features, extracted_urls = self.extract_urls(email_features)

                # Step 4: Scan patterns
                progress["value"] = 56
                self.root.after(0, lambda: status_var.set(analysis_steps[3]))
                time.sleep(0.5)

                pattern_features = self.scan_phishing_patterns(email_features)

                # Step 5: Run ML model
                progress["value"] = 70
                self.root.after(0, lambda: status_var.set(analysis_steps[4]))
                time.sleep(0.5)

                # Combine all features
                all_features = {**email_features, **sender_features, **url_features, **pattern_features}
                self.features_dict = all_features

                # Prepare features for the model
                features_for_model = self.prepare_features_for_model(all_features)

                # Run the model
                prediction_probability = self.run_model(features_for_model)

                # Step 6: Calculate probability
                progress["value"] = 84
                self.root.after(0, lambda: status_var.set(analysis_steps[5]))
                time.sleep(0.5)

                # Generate indicators based on features
                suspicious_indicators = self.generate_suspicious_indicators(all_features)

                # Step 7: Generate report
                progress["value"] = 100
                self.root.after(0, lambda: status_var.set(analysis_steps[6]))
                time.sleep(0.5)

                # Create results object
                is_phishing = prediction_probability >= 0.7  # Threshold

                self.analysis_results = {
                    'email': email_features,
                    'timestamp': self.current_datetime,
                    'probability': prediction_probability,
                    'is_phishing': is_phishing,
                    'indicators': suspicious_indicators,
                    'extracted_urls': extracted_urls,
                    'source': self.current_email['source'],
                    'features': all_features
                }

                # Store URLs
                self.add_suspicious_urls(extracted_urls, is_phishing)

                # Update analysis history
                self.update_analysis_history(self.current_email['source'], is_phishing, prediction_probability)

                # Close loading window if it still exists
                if loading_window.winfo_exists():
                    loading_window.destroy()

                # Update UI with results - use after to safely update from thread
                self.root.after(0, self.display_analysis_results)

                # Update status - use thread-safe update
                verdict = "Phishing detected" if is_phishing else "No phishing detected"
                status_type = "error" if is_phishing else "success"
                self.update_status(f"Analysis complete: {verdict}", status_type)

                # Update quick info - use after to safely update from thread
                self.root.after(0, lambda: self.analysis_status_label.config(
                    text="Analysis complete",
                    bootstyle="success"
                ))

                # Switch to report tab - use after to safely update from thread
                self.root.after(0, lambda: self.tab_control.select(self.report_tab))

            except Exception as e:
                print(f"Analysis error: {str(e)}")
                traceback.print_exc()

                # Close loading window if it still exists
                if loading_window.winfo_exists():
                    loading_window.destroy()

                # Show error message in the main thread
                self.root.after(0, lambda: Messagebox.show_error(
                    f"An error occurred during analysis: {str(e)}",
                    "Analysis Error"
                ))
                self.update_status("Error during analysis", "error")

        # Start analysis thread
        threading.Thread(target=run_analysis, daemon=True).start()

    def extract_email_features(self, email_data):
        """Extract features from email for analysis"""
        features = {}

        # Check if we have a parsed email or raw text
        if 'msg' in email_data and hasattr(email_data['msg'], 'get'):
            msg = email_data['msg']

            # Basic email fields
            features['from'] = str(msg.get('From', ''))
            features['to'] = str(msg.get('To', ''))
            features['subject'] = str(msg.get('Subject', ''))
            features['date'] = str(msg.get('Date', ''))
            features['return_path'] = str(msg.get('Return-Path', ''))
            features['reply_to'] = str(msg.get('Reply-To', ''))

            # Extract all headers for comprehensive analysis
            features['headers'] = {}
            for header, value in msg.items():
                features['headers'][header] = str(value)

            # Extract body
            body = ""
            if msg.is_multipart():
                for part in msg.iter_parts():
                    if part.get_content_type() == "text/plain":
                        try:
                            body += part.get_content()
                        except:
                            pass
            else:
                try:
                    if msg.get_content_type() == "text/plain":
                        body = msg.get_content()
                except:
                    pass

            features['body'] = body

            # Check for HTML content
            has_html = False
            if msg.is_multipart():
                for part in msg.iter_parts():
                    if part.get_content_type() == "text/html":
                        has_html = True
                        break
            else:
                has_html = msg.get_content_type() == "text/html"

            features['has_html'] = has_html

            # Check for attachments
            has_attachments = False
            attachment_count = 0
            if msg.is_multipart():
                for part in msg.iter_parts():
                    content_disposition = str(part.get("Content-Disposition", ""))
                    if "attachment" in content_disposition:
                        has_attachments = True
                        attachment_count += 1

            features['has_attachments'] = has_attachments
            features['attachment_count'] = attachment_count

        else:
            # We have raw text, not a parsed email
            # Try to extract basic features from text
            raw_text = str(email_data.get('msg', ''))

            # Try to extract headers
            headers_body = raw_text.split('\n\n', 1)
            headers_text = headers_body[0] if len(headers_body) > 0 else ""
            body = headers_body[1] if len(headers_body) > 1 else raw_text

            # Extract from header if present
            from_match = re.search(r'From:\s*(.*)', headers_text, re.IGNORECASE)
            features['from'] = from_match.group(1).strip() if from_match else ""

            # Extract to header if present
            to_match = re.search(r'To:\s*(.*)', headers_text, re.IGNORECASE)
            features['to'] = to_match.group(1).strip() if to_match else ""

            # Extract subject header if present
            subject_match = re.search(r'Subject:\s*(.*)', headers_text, re.IGNORECASE)
            features['subject'] = subject_match.group(1).strip() if subject_match else ""

            # Extract date header if present
            date_match = re.search(r'Date:\s*(.*)', headers_text, re.IGNORECASE)
            features['date'] = date_match.group(1).strip() if date_match else ""

            # Extract all headers
            features['headers'] = {}
            header_pattern = re.compile(r'^([^:]+):\s*(.*)$', re.MULTILINE)
            for match in header_pattern.finditer(headers_text):
                header_name = match.group(1).strip()
                header_value = match.group(2).strip()
                features['headers'][header_name] = header_value

            features['body'] = body
            features['has_html'] = '<html' in raw_text.lower() or '<body' in raw_text.lower()
            features['has_attachments'] = False
            features['attachment_count'] = 0

        return features

    def analyze_sender(self, email_features):
        """Analyze sender information for suspicious indicators"""
        sender_features = {}

        from_address = email_features.get('from', '')
        reply_to = email_features.get('reply_to', '')
        return_path = email_features.get('return_path', '')

        # Extract email addresses with regex
        from_email = self.extract_email_address(from_address)
        reply_to_email = self.extract_email_address(reply_to)
        return_path_email = self.extract_email_address(return_path)

        # Check for suspicious sender patterns
        sender_features['sender_domain_mismatch'] = self.check_domain_mismatch(from_email, reply_to_email,
                                                                               return_path_email)
        sender_features['sender_has_numbers'] = bool(re.search(r'\d{3,}', from_email))
        sender_features['sender_free_email'] = self.is_free_email_provider(from_email)
        sender_features['sender_suspicious_tld'] = self.has_suspicious_tld(from_email)
        sender_features['sender_has_suspicious_words'] = self.has_suspicious_sender_words(from_address)

        # Check display name vs email address
        display_name = self.extract_display_name(from_address)
        sender_features['sender_display_name_mismatch'] = self.check_display_name_mismatch(display_name, from_email)

        # Store raw values
        sender_features['sender_email'] = from_email
        sender_features['sender_display_name'] = display_name
        sender_features['sender_domain'] = self.extract_domain(from_email)

        return sender_features

    def extract_email_address(self, text):
        """Extract email address from a string"""
        if not text:
            return ""

        # Simple regex to extract email
        match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', text)
        return match.group(0) if match else ""

    def extract_display_name(self, from_string):
        """Extract display name from From header"""
        if not from_string:
            return ""

        # Check for format "Display Name <email@example.com>"
        match = re.search(r'^([^<]+)<', from_string)
        if match:
            return match.group(1).strip()
        return ""

    def extract_domain(self, email):
        """Extract domain from email address"""
        if '@' in email:
            return email.split('@')[1].lower()
        return ""

    def check_domain_mismatch(self, from_email, reply_to_email, return_path_email):
        """Check if email domains don't match between headers"""
        if not from_email:
            return False

        from_domain = self.extract_domain(from_email)

        # Check reply-to if it exists
        if reply_to_email and from_domain:
            reply_domain = self.extract_domain(reply_to_email)
            if reply_domain and reply_domain != from_domain:
                return True

        # Check return-path if it exists
        if return_path_email and from_domain:
            return_domain = self.extract_domain(return_path_email)
            if return_domain and return_domain != from_domain:
                return True

        return False

    def check_display_name_mismatch(self, display_name, email):
        """Check if display name tries to impersonate a different domain"""
        if not display_name or not email:
            return False

        # Convert to lowercase
        display_name = display_name.lower()
        email_domain = self.extract_domain(email).lower()

        # Check if display name contains a different domain than the email
        domain_pattern = r'\b([a-z0-9-]+\.[a-z0-9-]+(?:\.[a-z0-9-]+)*)\b'
        domains_in_display = re.findall(domain_pattern, display_name)

        for domain in domains_in_display:
            # If display name has a domain that's not the email domain
            if domain and len(domain.split('.')) > 1 and domain != email_domain:
                if not (domain in email_domain or email_domain in domain):
                    return True

        # Check for company names
        common_companies = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
                            'netflix', 'bank', 'chase', 'wells fargo', 'citibank', 'amex',
                            'american express']

        for company in common_companies:
            if company in display_name and company not in email_domain:
                return True

        return False

    def is_free_email_provider(self, email):
        """Check if the email is from a free provider"""
        if not email:
            return False

        domain = self.extract_domain(email)

        free_providers = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'aol.com', 'outlook.com',
            'mail.com', 'zoho.com', 'protonmail.com', 'icloud.com', 'yandex.com',
            'gmx.com', 'tutanota.com'
        ]

        return domain in free_providers

    def has_suspicious_tld(self, email):
        """Check if the email has a suspicious TLD"""
        if not email:
            return False

        domain = self.extract_domain(email)
        if not domain:
            return False

        tld = domain.split('.')[-1].lower() if '.' in domain else ''

        suspicious_tlds = [
            'xyz', 'top', 'club', 'online', 'site', 'cyou', 'icu',
            'work', 'live', 'click', 'link', 'bid', 'party'
        ]

        return tld in suspicious_tlds

    def has_suspicious_sender_words(self, sender_string):
        """Check if sender has suspicious words"""
        if not sender_string:
            return False

        sender_string = sender_string.lower()

        suspicious_words = [
            'security', 'verify', 'update', 'support', 'team', 'alert',
            'notification', 'account', 'confirm', 'secure', 'service',
            'admin', 'billing', 'payment', 'official', 'helpdesk'
        ]

        for word in suspicious_words:
            if word in sender_string:
                return True

        return False

    def extract_urls(self, email_features):
        """Extract and analyze URLs from email"""
        url_features = {}
        extracted_urls = []

        body = email_features.get('body', '')
        subject = email_features.get('subject', '')

        # Extract URLs from body and subject
        body_urls = self.find_urls(body)
        subject_urls = self.find_urls(subject)

        all_urls = body_urls + subject_urls
        extracted_urls = all_urls

        # URL analysis
        url_features['has_urls'] = len(all_urls) > 0
        url_features['url_count'] = len(all_urls)
        url_features['has_shortened_urls'] = self.has_shortened_urls(all_urls)
        url_features['has_ip_urls'] = self.has_ip_urls(all_urls)
        url_features['has_suspicious_tlds'] = self.has_urls_with_suspicious_tlds(all_urls)
        url_features['has_url_mismatch'] = self.has_url_text_mismatch(body)
        url_features['urls'] = all_urls

        return url_features, extracted_urls

    def find_urls(self, text):
        """Find URLs in text"""
        if not text:
            return []

        # URL regex pattern
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*(?:\?[/\w\.-=%&+]*)?'

        # Find all URLs
        urls = re.findall(url_pattern, text)

        # Remove duplicates while preserving order
        unique_urls = []
        for url in urls:
            if url not in unique_urls:
                unique_urls.append(url)

        return unique_urls

    def has_shortened_urls(self, urls):
        """Check if any URLs are shortened"""
        if not urls:
            return False

        shortening_services = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'tiny.cc', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly',
            'shorturl.at', 'clck.ru', 'bitly.com'
        ]

        for url in urls:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()

            if domain in shortening_services:
                return True

        return False

    def has_ip_urls(self, urls):
        """Check if any URLs use IP addresses"""
        if not urls:
            return False

        # IP address pattern
        ip_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

        for url in urls:
            if re.match(ip_pattern, url):
                return True

        return False

    def has_urls_with_suspicious_tlds(self, urls):
        """Check if URLs have suspicious TLDs"""
        if not urls:
            return False

        suspicious_tlds = [
            'xyz', 'top', 'club', 'online', 'site', 'cyou', 'icu',
            'work', 'live', 'click', 'link', 'bid', 'party', 'tk',
            'ml', 'ga', 'cf', 'gq', 'pw'
        ]

        for url in urls:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()

            if '.' in domain:
                tld = domain.split('.')[-1]
                if tld in suspicious_tlds:
                    return True

        return False

    def has_url_text_mismatch(self, body):
        """Check for URL text mismatch (e.g., <a href="evil.com">bank.com</a>)"""
        if not body:
            return False

        # This is a simple implementation - in HTML emails we would need more sophisticated parsing
        href_pattern = r'<a\s+(?:[^>]*?\s+)?href=(["\'])(.*?)\1[^>]*>(.*?)</a>'

        matches = re.findall(href_pattern, body, re.IGNORECASE)

        for match in matches:
            href_url = match[1]
            link_text = match[2]

            # Remove tags from link text
            link_text = re.sub(r'<[^>]+>', '', link_text)

            # Extract domains to compare
            href_domain = self.extract_domain_from_url(href_url)

            # Check if link text contains a URL
            text_urls = self.find_urls(link_text)
            if text_urls:
                text_domain = self.extract_domain_from_url(text_urls[0])
                if href_domain and text_domain and href_domain != text_domain:
                    return True

            # Check if link text contains domain-like text
            domain_pattern = r'[\w-]+\.[\w-]+(?:\.[\w-]+)*'
            domain_matches = re.findall(domain_pattern, link_text)

            for domain in domain_matches:
                if href_domain and domain != href_domain and '.' in domain:
                    return True

        return False

    def extract_domain_from_url(self, url):
        """Extract domain from URL"""
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            return domain
        except:
            return ""

    def scan_phishing_patterns(self, email_features):
        """Scan for common phishing patterns in the email"""
        pattern_features = {}

        subject = email_features.get('subject', '').lower()
        body = email_features.get('body', '').lower()

        # Check subject for suspicious words
        suspicious_subject_words = [
            'urgent', 'alert', 'verify', 'update', 'security', 'account',
            'suspended', 'unusual', 'confirm', 'verify', 'important',
            'password', 'login', 'immediately', 'attention', 'required'
        ]

        pattern_features['subject_has_urgency'] = any(word in subject for word in suspicious_subject_words)

        # Check for urgency phrases in body
        urgency_phrases = [
            'act now', 'urgent action', 'immediate action', 'expires soon',
            'limited time', '24 hours', 'immediately', 'as soon as possible',
            'failure to comply', 'account will be', 'before it\'s too late',
            'right away', 'time sensitive'
        ]

        pattern_features['body_has_urgency'] = any(phrase in body for phrase in urgency_phrases)

        # Check for sensitive data requests
        sensitive_requests = [
            'password', 'credit card', 'account number', 'credentials',
            'social security', 'ssn', 'banking details', 'personal details',
            'pin', 'security question', 'mother\'s maiden name', 'login',
            'username and password'
        ]

        pattern_features['requests_sensitive_data'] = any(phrase in body for phrase in sensitive_requests)

        # Check for suspicious claims
        suspicious_claims = [
            'won', 'winner', 'lottery', 'selected', 'prize', 'million',
            'reward', 'inheritance', 'claim your', 'you have been chosen',
            'congratulations', 'exclusive offer', 'free gift', 'jackpot'
        ]

        pattern_features['has_suspicious_claims'] = any(phrase in body for phrase in suspicious_claims)

        # Check for poor grammar/spelling
        grammar_indicators = [
            'kindly', 'dear valued', 'dear costumer', 'dear customer',
            'your account will closed', 'verify you account', 'your are',
            'we detected unusual', 'we detected suspicious'
        ]

        pattern_features['has_poor_grammar'] = any(phrase in body for phrase in grammar_indicators)

        # Check for threatening language
        threatening_phrases = [
            'suspended', 'terminated', 'closed', 'deleted', 'unauthorized',
            'suspicious activity', 'unusual activity', 'breach',
            'compromised', 'locked', 'restricted', 'limitation'
        ]

        pattern_features['has_threatening_language'] = any(phrase in body for phrase in threatening_phrases)

        return pattern_features

    def prepare_features_for_model(self, all_features):
        """Extract model features from email features dictionary"""
        try:
            # Extract email content
            email_text = ""

            # Extract body text
            if 'body' in all_features:
                email_text += all_features['body'] + " "

            # Include subject
            if 'subject' in all_features:
                email_text += all_features['subject'] + " "

            # Include from field
            if 'from' in all_features:
                email_text += all_features['from'] + " "

            # Extract standardized features from text
            features = self.extract_features_from_text(email_text)

            # Ensure we have a valid feature array
            if features is None or len(features) != self.model_feature_count:
                # Create a default feature array of the right size if needed
                features = np.zeros(self.model_feature_count)

            # Reshape for model prediction
            return features.reshape(1, -1)

        except Exception as e:
            print(f"Error preparing features: {e}")
            # Return safe default
            return np.zeros((1, self.model_feature_count))

    def run_model(self, features):
        """Run the machine learning model on the features"""
        try:
            # Check if model is loaded
            if self.loaded_model is None:
                print("No model loaded")
                return 0.5  # Default value if no model

            # Ensure features have correct shape
            if features.shape[1] != self.model_feature_count:
                print(f"Feature count mismatch. Expected {self.model_feature_count}, got {features.shape[1]}")
                # Resize features if needed
                new_features = np.zeros((1, self.model_feature_count))
                # Copy as many features as we can
                common_size = min(features.shape[1], self.model_feature_count)
                new_features[0, :common_size] = features[0, :common_size]
                features = new_features

            # Run prediction if model has the predict method
            if hasattr(self.loaded_model, 'predict_proba'):
                # Get probability of phishing class
                prediction = self.loaded_model.predict_proba(features)
                return float(prediction[0][1])  # Probability of phishing (class 1)
            elif hasattr(self.loaded_model, 'predict'):
                # Get binary prediction
                prediction = self.loaded_model.predict(features)
                return float(prediction[0])  # Convert to float for safety
            else:
                # Fallback if model doesn't have predict method
                print("Model doesn't have predict method")
                return 0.5  # Default value

        except Exception as e:
            print(f"Error running model: {str(e)}")
            traceback.print_exc()
            return 0.5  # Default value in case of error


    def generate_suspicious_indicators(self, features):
        """Generate list of suspicious indicators based on features"""
        indicators = []

        # Sender indicators
        if features.get('sender_domain_mismatch', False):
            indicators.append({
                'type': 'critical',
                'name': 'Sender domain mismatch',
                'description': "The email's From, Reply-To, or Return-Path addresses use different domains, which is a common phishing tactic."
            })

        if features.get('sender_display_name_mismatch', False):
            indicators.append({
                'type': 'critical',
                'name': 'Display name spoofing',
                'description': "The sender's display name tries to impersonate a trusted organization that doesn't match the actual email domain."
            })

        if features.get('sender_has_suspicious_words', False):
            indicators.append({
                'type': 'warning',
                'name': 'Suspicious sender name',
                'description': "The sender's name contains terms commonly used in phishing attempts, like 'security', 'support', or 'admin'."
            })

        # URL indicators
        if features.get('has_shortened_urls', False):
            indicators.append({
                'type': 'critical',
                'name': 'Shortened URLs',
                'description': "The email contains shortened URLs that hide the actual destination, a common phishing tactic."
            })

        if features.get('has_ip_urls', False):
            indicators.append({
                'type': 'critical',
                'name': 'IP address URLs',
                'description': "The email contains links with raw IP addresses instead of domain names, which is highly suspicious."
            })

        if features.get('has_suspicious_tlds', False):
            indicators.append({
                'type': 'warning',
                'name': 'Suspicious URL domains',
                'description': "The email contains URLs with suspicious or uncommon top-level domains often used in phishing."
            })

        if features.get('has_url_mismatch', False):
            indicators.append({
                'type': 'critical',
                'name': 'URL display mismatch',
                'description': "The email contains links where the visible text differs from the actual URL destination."
            })

        # Content indicators
        if features.get('subject_has_urgency', False) or features.get('body_has_urgency', False):
            indicators.append({
                'type': 'warning',
                'name': 'Creates false urgency',
                'description': "The email creates a false sense of urgency to pressure you into taking immediate action without thinking."
            })

        if features.get('requests_sensitive_data', False):
            indicators.append({
                'type': 'critical',
                'name': 'Requests sensitive information',
                'description': "The email asks for passwords, account details, or other sensitive personal information."
            })

        if features.get('has_suspicious_claims', False):
            indicators.append({
                'type': 'warning',
                'name': 'Suspicious claims or offers',
                'description': "The email contains claims about prizes, rewards, or offers that are likely fraudulent."
            })

        if features.get('has_poor_grammar', False):
            indicators.append({
                'type': 'info',
                'name': 'Poor grammar or spelling',
                'description': "The email contains grammatical errors or unusual phrasing often seen in phishing attempts."
            })

        if features.get('has_threatening_language', False):
            indicators.append({
                'type': 'warning',
                'name': 'Contains threats or warnings',
                'description': "The email threatens negative consequences if you don't take immediate action."
            })

        return indicators

    def display_analysis_results(self):
        """Display the analysis results in the report tab"""
        # Check if we have results
        if not self.analysis_results:
            return

        # Clear the report tab
        for widget in self.report_tab.winfo_children():
            widget.destroy()

        # Container with padding
        container = ttk.Frame(self.report_tab)
        container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # Create two columns
        left_col = ttk.Frame(container)
        left_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        right_col = ttk.Frame(container)
        right_col.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))

        # Left column - Summary and primary results
        self.create_summary_section(left_col)
        self.create_indicators_section(left_col)

        # Right column - Email details and technical analysis
        self.create_email_details_section(right_col)
        self.create_urls_section(right_col)

        # Add action buttons at the bottom
        self.create_action_buttons(container)

    def create_summary_section(self, parent):
        """Create the summary section of the report"""
        # Summary frame
        summary_frame = ttk.LabelFrame(parent, text="Analysis Summary")
        summary_frame.pack(fill=tk.X, pady=(0, 15))

        # Get values from results
        is_phishing = self.analysis_results.get('is_phishing', False)
        probability = self.analysis_results.get('probability', 0.0)

        # Summary content
        summary_content = ttk.Frame(summary_frame)
        summary_content.pack(fill=tk.X, padx=15, pady=15)

        # Verdict with icon
        verdict_frame = ttk.Frame(summary_content)
        verdict_frame.pack(fill=tk.X, pady=(0, 15))

        if is_phishing:
            verdict_icon = "🔴"  # Red circle for phishing
            verdict_text = "PHISHING DETECTED"
            verdict_color = "danger"
        else:
            verdict_icon = "🟢"  # Green circle for safe
            verdict_text = "NO PHISHING DETECTED"
            verdict_color = "success"

        ttk.Label(
            verdict_frame,
            text=verdict_icon,
            font=("Segoe UI", 24)
        ).pack(side=tk.LEFT, padx=(0, 10))

        verdict_text_frame = ttk.Frame(verdict_frame)
        verdict_text_frame.pack(side=tk.LEFT)

        ttk.Label(
            verdict_text_frame,
            text=verdict_text,
            font=("Segoe UI", 16, "bold"),
            bootstyle=verdict_color
        ).pack(anchor=tk.W)

        ttk.Label(
            verdict_text_frame,
            text=f"Confidence: {probability:.1%}",
            bootstyle="secondary"
        ).pack(anchor=tk.W)

        # Probability meter
        meter_frame = ttk.Frame(summary_content)
        meter_frame.pack(fill=tk.X, pady=(0, 15))

        ttk.Label(
            meter_frame,
            text="Phishing Probability:",
            font=("Segoe UI", 10, "bold")
        ).pack(anchor=tk.W, pady=(0, 5))

        # Probability bar
        prob_bar = ttk.Progressbar(
            meter_frame,
            value=probability * 100,
            length=300,
            bootstyle=verdict_color
        )
        prob_bar.pack(fill=tk.X)

        # Scale labels
        scale_frame = ttk.Frame(meter_frame)
        scale_frame.pack(fill=tk.X)

        ttk.Label(
            scale_frame,
            text="0%",
            bootstyle="secondary"
        ).pack(side=tk.LEFT)

        ttk.Label(
            scale_frame,
            text="50%",
            bootstyle="secondary"
        ).pack(side=tk.LEFT, padx=(125, 0))

        ttk.Label(
            scale_frame,
            text="100%",
            bootstyle="secondary"
        ).pack(side=tk.RIGHT)

        # Summary text
        summary_text = f"The email was analyzed on {self.current_datetime}. "

        if is_phishing:
            summary_text += "Our analysis indicates this is very likely a phishing attempt. "
            summary_text += "We recommend you do NOT click any links, download attachments, or reply to this message."
        else:
            summary_text += "Our analysis suggests this email is likely safe, "
            summary_text += "but always exercise caution with unexpected emails."

        ttk.Label(
            summary_content,
            text=summary_text,
            wraplength=400,
            justify=tk.LEFT
        ).pack(fill=tk.X)

    def create_indicators_section(self, parent):
        """Create the indicators section of the report"""
        # Get indicators from results
        indicators = self.analysis_results.get('indicators', [])

        if not indicators:
            return

        # Indicators frame
        indicators_frame = ttk.LabelFrame(parent, text="Suspicious Indicators")
        indicators_frame.pack(fill=tk.BOTH, expand=True)

        # Container for indicators with scrolling
        indicators_canvas = ttk.Canvas(indicators_frame)
        scrollbar = ttk.Scrollbar(indicators_frame, orient="vertical", command=indicators_canvas.yview)
        scrollable_frame = ttk.Frame(indicators_canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: indicators_canvas.configure(scrollregion=indicators_canvas.bbox("all"))
        )

        indicators_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        indicators_canvas.configure(yscrollcommand=scrollbar.set)

        indicators_canvas.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.pack(side="right", fill="y", pady=10)

        # Add indicators to the frame
        for i, indicator in enumerate(indicators):
            self.create_indicator_item(scrollable_frame, indicator, i)

    def create_indicator_item(self, parent, indicator, index):
        """Create an individual indicator item"""
        # Get indicator data
        indicator_type = indicator.get('type', 'info')
        indicator_name = indicator.get('name', 'Unknown')
        indicator_desc = indicator.get('description', '')

        # Map type to style and icon
        style_map = {
            'critical': ('danger', '⚠️'),
            'warning': ('warning', '⚠️'),
            'info': ('info', 'ℹ️')
        }

        style, icon = style_map.get(indicator_type, style_map['info'])

        # Create frame for this indicator
        item_frame = ttk.Frame(parent)
        item_frame.pack(fill=tk.X, pady=(0, 10))

        # Icon and name row
        header_frame = ttk.Frame(item_frame)
        header_frame.pack(fill=tk.X)

        ttk.Label(
            header_frame,
            text=icon,
            font=("Segoe UI", 12)
        ).pack(side=tk.LEFT)

        ttk.Label(
            header_frame,
            text=indicator_name,
            font=("Segoe UI", 10, "bold"),
            bootstyle=style
        ).pack(side=tk.LEFT, padx=(5, 0))

        # Description
        ttk.Label(
            item_frame,
            text=indicator_desc,
            wraplength=370,
            justify=tk.LEFT
        ).pack(fill=tk.X, padx=(25, 0))

        # Add separator if not the last item
        if index < len(self.analysis_results.get('indicators', [])) - 1:
            ttk.Separator(parent).pack(fill=tk.X, pady=(0, 10))

    def create_email_details_section(self, parent):
        """Create the email details section"""
        # Email details frame
        details_frame = ttk.LabelFrame(parent, text="Email Details")
        details_frame.pack(fill=tk.X, pady=(0, 15))

        details_content = ttk.Frame(details_frame)
        details_content.pack(fill=tk.X, padx=15, pady=15)

        # Get email data
        email_data = self.analysis_results.get('email', {})

        # Create scrollable frame for headers with fixed height
        headers_canvas = ttk.Canvas(details_content, height=200)  # Set height here, not in pack
        headers_scrollbar = ttk.Scrollbar(details_content, orient="vertical", command=headers_canvas.yview)
        headers_frame = ttk.Frame(headers_canvas)

        headers_frame.bind(
            "<Configure>",
            lambda e: headers_canvas.configure(scrollregion=headers_canvas.bbox("all"))
        )

        headers_canvas.create_window((0, 0), window=headers_frame, anchor="nw")
        headers_canvas.configure(yscrollcommand=headers_scrollbar.set)

        # Pack widgets properly
        headers_canvas.pack(side="left", fill="both", expand=True)  # Height removed from here
        headers_scrollbar.pack(side="right", fill="y")

        # Details table - include all available headers
        details = []

        # Add standard headers first
        standard_headers = [
            ("From:", email_data.get('from', 'Unknown')),
            ("To:", email_data.get('to', 'Unknown')),
            ("Subject:", email_data.get('subject', 'No Subject')),
            ("Date:", email_data.get('date', 'Unknown')),
            ("Source:", self.analysis_results.get('source', 'Manual input'))
        ]

        details.extend(standard_headers)

        # Add additional headers if available
        if 'headers' in email_data and isinstance(email_data['headers'], dict):
            for header, value in email_data['headers'].items():
                # Skip headers we already included
                if header.lower() not in ['from', 'to', 'subject', 'date']:
                    details.append((f"{header}:", value))

        # Add headers to the frame
        for i, (label, value) in enumerate(details):
            ttk.Label(
                headers_frame,
                text=label,
                font=("Segoe UI", 10, "bold")
            ).grid(row=i, column=0, sticky=tk.W, pady=2)

            ttk.Label(
                headers_frame,
                text=value,
                wraplength=300
            ).grid(row=i, column=1, sticky=tk.W, padx=(10, 0), pady=2)

    def create_urls_section(self, parent):
        """Create the URLs section"""
        # Get URLs from analysis
        urls = self.analysis_results.get('extracted_urls', [])

        if not urls:
            return

        # URLs frame
        urls_frame = ttk.LabelFrame(parent, text="Detected URLs")
        urls_frame.pack(fill=tk.BOTH, expand=True)

        urls_content = ttk.Frame(urls_frame)
        urls_content.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # URL count
        ttk.Label(
            urls_content,
            text=f"Found {len(urls)} URLs in this email:",
            font=("Segoe UI", 10, "bold")
        ).pack(anchor=tk.W, pady=(0, 10))

        # URL list with scrolling
        url_canvas = ttk.Canvas(urls_content)
        url_scrollbar = ttk.Scrollbar(urls_content, orient="vertical", command=url_canvas.yview)
        url_frame = ttk.Frame(url_canvas)

        url_frame.bind(
            "<Configure>",
            lambda e: url_canvas.configure(scrollregion=url_canvas.bbox("all"))
        )

        url_canvas.create_window((0, 0), window=url_frame, anchor="nw")
        url_canvas.configure(yscrollcommand=url_scrollbar.set)

        url_canvas.pack(side="left", fill="both", expand=True)
        url_scrollbar.pack(side="right", fill="y")

        # Add URLs to the list
        for i, url in enumerate(urls):
            url_item = ttk.Frame(url_frame)
            url_item.pack(fill=tk.X, pady=(0, 5))

            ttk.Label(
                url_item,
                text=f"{i + 1}.",
                font=("Segoe UI", 10, "bold")
            ).pack(side=tk.LEFT)

            ttk.Label(
                url_item,
                text=url,
                wraplength=300
            ).pack(side=tk.LEFT, padx=(5, 0))

    def create_action_buttons(self, parent):
        """Create action buttons for the report"""
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, pady=(15, 0))

        # Phishing verdict
        is_phishing = self.analysis_results.get('is_phishing', False)

        if is_phishing:
            # Report phishing button
            ttk.Button(
                button_frame,
                text="Report as Phishing",
                bootstyle="danger",
                command=self.report_phishing
            ).pack(side=tk.LEFT, padx=(0, 10))

            # Block sender button
            ttk.Button(
                button_frame,
                text="Block Sender",
                bootstyle="warning-outline",
                command=self.block_sender
            ).pack(side=tk.LEFT)

        else:
            # Mark as safe button
            ttk.Button(
                button_frame,
                text="Mark as Safe",
                bootstyle="success",
                command=self.mark_as_safe
            ).pack(side=tk.LEFT, padx=(0, 10))

            # Report false negative button
            ttk.Button(
                button_frame,
                text="Report as Phishing",
                bootstyle="warning-outline",
                command=self.report_phishing
            ).pack(side=tk.LEFT)

        # Save report button
        ttk.Button(
            button_frame,
            text="Save Report",
            bootstyle="info-outline",
            command=self.save_report
        ).pack(side=tk.RIGHT)

    def report_phishing(self):
        """Report email as phishing"""
        Messagebox.show_info(
            "This feature would typically send the phishing email to your organization's security team or to services like Google's Phishing Protection or Microsoft's Report Message.",
            "Report Phishing"
        )

    def block_sender(self):
        """Block sender of the email"""
        # Get sender email
        if not self.analysis_results:
            return

        sender = self.analysis_results.get('email', {}).get('from', '')

        Messagebox.show_info(
            f"This would typically add the sender '{sender}' to your email client's block list. This is a placeholder for that functionality.",
            "Block Sender"
        )

    def mark_as_safe(self):
        """Mark email as safe"""
        Messagebox.show_info(
            "This would typically add the sender to your safe senders list and improve the model through feedback. This is a placeholder for that functionality.",
            "Mark as Safe"
        )

    def save_report(self):
        """Save analysis report to file"""
        if not self.analysis_results:
            return

        # Get a file path to save to
        file_path = filedialog.asksaveasfilename(
            title="Save Report",
            filetypes=[("HTML files", "*.html"), ("Text files", "*.txt"), ("All files", "*.*")],
            defaultextension=".html"
        )

        if not file_path:
            return

        try:
            # Simple HTML report
            if file_path.endswith('.html'):
                self.save_html_report(file_path)
            else:
                self.save_text_report(file_path)

            self.update_status(f"Report saved to {os.path.basename(file_path)}", "success")

        except Exception as e:
            print(f"Error saving report: {e}")
            traceback.print_exc()
            Messagebox.show_error(
                f"Error saving report: {str(e)}",
                "Save Error"
            )

    def save_html_report(self, file_path):
        """Save report as HTML file"""
        # Get data
        is_phishing = self.analysis_results.get('is_phishing', False)
        probability = self.analysis_results.get('probability', 0.0)
        email_data = self.analysis_results.get('email', {})
        indicators = self.analysis_results.get('indicators', [])
        urls = self.analysis_results.get('extracted_urls', [])

        # Verdict text
        verdict = "PHISHING DETECTED" if is_phishing else "NO PHISHING DETECTED"
        verdict_color = "#dc3545" if is_phishing else "#28a745"

        # Create HTML
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Phishing Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ text-align: center; margin-bottom: 20px; }}
                .verdict {{ color: {verdict_color}; font-size: 24px; font-weight: bold; }}
                .section {{ margin-bottom: 20px; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }}
                .critical {{ color: #dc3545; }}
                .warning {{ color: #ffc107; }}
                .info {{ color: #17a2b8; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
                .footer {{ text-align: center; font-size: 12px; color: #666; margin-top: 30px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Phishing Email Analysis Report</h1>
                <p>Generated on {self.current_datetime}</p>
                <p class="verdict">{verdict}</p>
                <p>Phishing Probability: {probability:.1%}</p>
            </div>

            <div class="section">
                <h2>Email Details</h2>
                <table>
        """

        # Add email headers to table
        for header, value in email_data.items():
            if header != 'headers' and header != 'body':
                html += f"<tr><th>{header.title()}</th><td>{value}</td></tr>\n"

        # Add source
        html += f"""
                    <tr><th>Source</th><td>{self.analysis_results.get('source', 'Manual input')}</td></tr>
                </table>
            </div>
        """

        # Add indicators section
        if indicators:
            html += """
            <div class="section">
                <h2>Suspicious Indicators</h2>
                <ul>
            """

            for indicator in indicators:
                indicator_type = indicator.get('type', 'info')
                indicator_name = indicator.get('name', 'Unknown')
                indicator_desc = indicator.get('description', '')

                html += f"""
                <li>
                    <span class="{indicator_type}"><strong>{indicator_name}</strong></span>
                    <p>{indicator_desc}</p>
                </li>
                """

            html += """
                </ul>
            </div>
            """

        # Add URLs section
        if urls:
            html += f"""
            <div class="section">
                <h2>Detected URLs ({len(urls)})</h2>
                <ol>
            """

            for url in urls:
                html += f"<li>{url}</li>"

            html += """
                </ol>
            </div>
            """

        # Add all email headers section if available
        if 'headers' in email_data and isinstance(email_data['headers'], dict):
            html += """
            <div class="section">
                <h2>All Email Headers</h2>
                <table>
            """

            for header, value in email_data['headers'].items():
                html += f"<tr><th>{header}</th><td>{value}</td></tr>\n"

            html += """
                </table>
            </div>
            """

        # Add footer and close HTML
        html += f"""
            <div class="footer">
                <p>Generated by Phishing Detector v1.0.0</p>
                <p>&copy; 2025 {self.current_user}</p>
            </div>
        </body>
        </html>
        """

        # Write to file
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(html)

    def save_text_report(self, file_path):
        """Save report as plain text file"""
        # Get data
        is_phishing = self.analysis_results.get('is_phishing', False)
        probability = self.analysis_results.get('probability', 0.0)
        email_data = self.analysis_results.get('email', {})
        indicators = self.analysis_results.get('indicators', [])
        urls = self.analysis_results.get('extracted_urls', [])

        # Verdict text
        verdict = "PHISHING DETECTED" if is_phishing else "NO PHISHING DETECTED"

        # Create text report
        report = f"""
PHISHING EMAIL ANALYSIS REPORT
Generated on {self.current_datetime}

VERDICT: {verdict}
Phishing Probability: {probability:.1%}

EMAIL DETAILS:
"""

        # Add standard email fields
        for key, value in email_data.items():
            if key != 'headers' and key != 'body':
                report += f"{key.title()}: {value}\n"

        report += f"Source: {self.analysis_results.get('source', 'Manual input')}\n"

        # Add indicators section
        if indicators:
            report += "\nSUSPICIOUS INDICATORS:\n"

            for i, indicator in enumerate(indicators):
                indicator_type = indicator.get('type', 'info').upper()
                indicator_name = indicator.get('name', 'Unknown')
                indicator_desc = indicator.get('description', '')

                report += f"{i + 1}. [{indicator_type}] {indicator_name}\n   {indicator_desc}\n\n"

        # Add URLs section
        if urls:
            report += f"\nDETECTED URLS ({len(urls)}):\n"

            for i, url in enumerate(urls):
                report += f"{i + 1}. {url}\n"

        # Add all email headers section if available
        if 'headers' in email_data and isinstance(email_data['headers'], dict):
            report += "\nALL EMAIL HEADERS:\n"

            for header, value in email_data['headers'].items():
                report += f"{header}: {value}\n"

        # Add footer
        report += f"\nGenerated by Phishing Detector v1.0.0\n© 2025 {self.current_user}"

        # Write to file
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(report)

    def add_url_dialog(self):
        """Show dialog to manually add a suspicious URL"""
        # Create dialog window
        dialog = ttk.Toplevel(self.root)
        dialog.title("Add Suspicious URL")
        dialog.geometry("500x300")

        # Center the dialog
        screen_width = dialog.winfo_screenwidth()
        screen_height = dialog.winfo_screenheight()
        x = (screen_width - 500) // 2
        y = (screen_height - 300) // 2
        dialog.geometry(f"500x300+{x}+{y}")

        # Make it modal
        dialog.transient(self.root)
        dialog.grab_set()

        # Content
        content_frame = ttk.Frame(dialog)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        ttk.Label(
            content_frame,
            text="Add Suspicious URL",
            font=("Segoe UI", 14, "bold")
        ).pack(pady=(0, 15))

        # URL input
        url_frame = ttk.Frame(content_frame)
        url_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(
            url_frame,
            text="URL:",
            width=10
        ).pack(side=tk.LEFT)

        url_var = StringVar()
        url_entry = ttk.Entry(
            url_frame,
            textvariable=url_var,
            width=50
        )
        url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        url_entry.focus()

        # Source input
        source_frame = ttk.Frame(content_frame)
        source_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(
            source_frame,
            text="Source:",
            width=10
        ).pack(side=tk.LEFT)

        source_var = StringVar(value="Manual entry")
        source_entry = ttk.Entry(
            source_frame,
            textvariable=source_var,
            width=50
        )
        source_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Risk level
        risk_frame = ttk.Frame(content_frame)
        risk_frame.pack(fill=tk.X, pady=(0, 15))

        ttk.Label(
            risk_frame,
            text="Risk Level:",
            width=10
        ).pack(side=tk.LEFT)

        risk_var = StringVar(value="Medium")
        risk_combo = ttk.Combobox(
            risk_frame,
            textvariable=risk_var,
            values=["Low", "Medium", "High", "Critical"],
            width=15
        )
        risk_combo.pack(side=tk.LEFT)

        # Buttons
        button_frame = ttk.Frame(content_frame)
        button_frame.pack(fill=tk.X, pady=(15, 0))

        ttk.Button(
            button_frame,
            text="Cancel",
            bootstyle="secondary",
            command=dialog.destroy
        ).pack(side=tk.RIGHT, padx=(10, 0))

        ttk.Button(
            button_frame,
            text="Add URL",
            bootstyle="primary",
            command=lambda: self.add_url_from_dialog(url_var.get(), source_var.get(), risk_var.get(), dialog)
        ).pack(side=tk.RIGHT)

    def add_url_from_dialog(self, url, source, risk_level, dialog):
        """Add URL from dialog input"""
        if not url:
            Messagebox.show_warning("Please enter a URL", "Missing URL")
            return

        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        try:
            # Create URL entry
            url_entry = {
                'url': url,
                'source': source,
                'date_added': self.current_datetime,
                'risk_level': risk_level
            }

            # Add to list and save
            self.suspicious_urls.append(url_entry)
            self.save_suspicious_urls()

            # Update display
            self.display_suspicious_urls()

            # Close dialog
            dialog.destroy()

            self.update_status(f"Added suspicious URL: {url}", "info")

        except Exception as e:
            print(f"Error adding URL: {e}")
            traceback.print_exc()
            Messagebox.show_error(f"Error adding URL: {str(e)}", "Error")

    def remove_selected_url(self):
        """Remove selected URL from the list"""
        # Get selected item
        selected = self.url_tree.selection()

        if not selected:
            Messagebox.show_info("Please select a URL to remove", "No Selection")
            return

        # Get URL from the selected item
        item_id = selected[0]
        item_index = int(self.url_tree.item(item_id, "text")) - 1

        if 0 <= item_index < len(self.suspicious_urls):
            url = self.suspicious_urls[item_index]['url']

            # Confirm deletion
            confirm = Messagebox.show_question(
                f"Are you sure you want to remove the URL:\n{url}",
                "Confirm Removal"
            )

            if confirm == "yes":
                # Remove from list and save
                del self.suspicious_urls[item_index]
                self.save_suspicious_urls()

                # Update display
                self.display_suspicious_urls()

                self.update_status(f"Removed URL: {url}", "info")

    def export_urls(self):
        """Export suspicious URLs to a file"""
        if not self.suspicious_urls:
            Messagebox.show_info("No URLs to export", "Export URLs")
            return

        # Get a file path to save to
        file_path = filedialog.asksaveasfilename(
            title="Export URLs",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"), ("All files", "*.*")],
            defaultextension=".csv"
        )

        if not file_path:
            return

        try:
            # Export based on file extension
            if file_path.endswith('.csv'):
                self.export_urls_csv(file_path)
            elif file_path.endswith('.json'):
                self.export_urls_json(file_path)
            else:
                self.export_urls_csv(file_path)  # Default to CSV

            self.update_status(f"Exported URLs to {os.path.basename(file_path)}", "success")

        except Exception as e:
            print(f"Error exporting URLs: {e}")
            traceback.print_exc()
            Messagebox.show_error(
                f"Error exporting URLs: {str(e)}",
                "Export Error"
            )

    def export_urls_csv(self, file_path):
        """Export URLs to CSV file"""
        with open(file_path, 'w', newline='') as file:
            writer = csv.writer(file)

            # Write header
            writer.writerow(['URL', 'Source', 'Date Added', 'Risk Level'])

            # Write data
            for url_entry in self.suspicious_urls:
                writer.writerow([
                    url_entry.get('url', ''),
                    url_entry.get('source', ''),
                    url_entry.get('date_added', ''),
                    url_entry.get('risk_level', '')
                ])

    def export_urls_json(self, file_path):
        """Export URLs to JSON file"""
        with open(file_path, 'w') as file:
            json.dump(self.suspicious_urls, file, indent=2)

    def load_suspicious_urls(self):
        """Load suspicious URLs from file"""
        try:
            if os.path.exists(self.urls_file):
                with open(self.urls_file, 'r') as file:
                    self.suspicious_urls = json.load(file)
            else:
                self.suspicious_urls = []
        except Exception as e:
            print(f"Error loading suspicious URLs: {e}")
            traceback.print_exc()
            self.suspicious_urls = []

    def save_suspicious_urls(self):
        """Save suspicious URLs to file"""
        try:
            with open(self.urls_file, 'w') as file:
                json.dump(self.suspicious_urls, file, indent=2)
        except Exception as e:
            print(f"Error saving suspicious URLs: {e}")
            traceback.print_exc()

    def display_suspicious_urls(self):
        """Display suspicious URLs in the treeview"""
        # Clear existing items
        for item in self.url_tree.get_children():
            self.url_tree.delete(item)

        # Add URLs to the treeview
        for i, url_entry in enumerate(self.suspicious_urls):
            values = (
                str(i + 1),
                url_entry.get('url', ''),
                url_entry.get('source', ''),
                url_entry.get('date_added', ''),
                url_entry.get('risk_level', '')
            )

            self.url_tree.insert('', 'end', text=str(i + 1), values=values)

    def add_suspicious_urls(self, urls, is_phishing):
        """Add URLs from analysis to suspicious URLs list"""
        if not urls or not is_phishing:
            return

        # Add each URL
        for url in urls:
            # Check if URL already exists
            if any(entry.get('url') == url for entry in self.suspicious_urls):
                continue

            # Create new entry
            url_entry = {
                'url': url,
                'source': self.current_email.get('source', 'Analysis'),
                'date_added': self.current_datetime,
                'risk_level': 'High'
            }

            self.suspicious_urls.append(url_entry)

        # Save updated list
        self.save_suspicious_urls()

        # Update display if we're on the URLs tab
        if self.tab_control.tab(self.tab_control.select(), "text") == "🔗 Suspicious URLs":
            self.display_suspicious_urls()

    def load_analysis_history(self):
        """Load analysis history from file"""
        try:
            # Initialize empty history if file doesn't exist
            if not os.path.exists(self.history_file):
                with open(self.history_file, 'w') as file:
                    json.dump([], file)
                history = []
            else:
                # Try to load existing history
                try:
                    with open(self.history_file, 'r') as file:
                        # Create empty file if reading fails
                        file_content = file.read().strip()
                        if not file_content:
                            history = []
                        else:
                            history = json.loads(file_content)
                except json.JSONDecodeError as e:
                    print(f"Error loading history: {e}")
                    # Reset history file if corrupted
                    with open(self.history_file, 'w') as file:
                        json.dump([], file)
                    history = []

            # Update previous analysis display
            self.update_history_display(history)

        except Exception as e:
            print(f"Error loading history: {e}")
            traceback.print_exc()
            # Reset history file if general error
            try:
                with open(self.history_file, 'w') as file:
                    json.dump([], file)
            except:
                pass
            history = []
            self.update_history_display(history)

    def update_analysis_history(self, source, is_phishing, probability):
        """Update analysis history with new result"""
        try:
            # Load current history
            history = []

            # Initialize empty history if file doesn't exist
            if not os.path.exists(self.history_file):
                with open(self.history_file, 'w') as file:
                    json.dump([], file)
            else:
                # Try to load existing history
                try:
                    with open(self.history_file, 'r') as file:
                        # Handle empty file
                        file_content = file.read().strip()
                        if not file_content:
                            history = []
                        else:
                            history = json.loads(file_content)
                except json.JSONDecodeError:
                    # Reset history if corrupted
                    history = []

            # Create entry using primitive types for JSON compatibility
            entry = {
                'source': source,
                'timestamp': self.current_datetime,
                'is_phishing': 1 if is_phishing else 0,  # Use integers instead of booleans
                'probability': float(probability)  # Ensure it's a float
            }

            # Add to history (keep most recent 10)
            history.insert(0, entry)
            if len(history) > 10:
                history = history[:10]

            # Save history
            with open(self.history_file, 'w') as file:
                json.dump(history, file)

            # Update display
            self.update_history_display(history)

        except Exception as e:
            print(f"Error saving history: {e}")
            traceback.print_exc()

    def update_history_display(self, history):
        """Update the display of previous analyses"""
        # Clear current display
        for widget in self.prev_results_frame.winfo_children():
            widget.destroy()

        if not history:
            # Show placeholder
            ttk.Label(
                self.prev_results_frame,
                text="No previous analyses",
                bootstyle="secondary"
            ).pack(pady=5)
            return

        # Add history items
        for i, entry in enumerate(history[:5]):  # Show only most recent 5
            # Get values
            source = entry.get('source', 'Unknown')
            timestamp = entry.get('timestamp', '')
            is_phishing = bool(entry.get('is_phishing', 0))  # Convert back to boolean
            probability = float(entry.get('probability', 0.0))

            # Create item frame
            item_frame = ttk.Frame(self.prev_results_frame)
            item_frame.pack(fill=tk.X, pady=(0, 5))

            # Status indicator
            indicator = "🔴" if is_phishing else "🟢"

            ttk.Label(
                item_frame,
                text=indicator,
                font=("Segoe UI", 10)
            ).pack(side=tk.LEFT)

            # Source and timestamp
            info_frame = ttk.Frame(item_frame)
            info_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))

            ttk.Label(
                info_frame,
                text=source,
                font=("Segoe UI", 9, "bold")
            ).pack(anchor=tk.W)

            ttk.Label(
                info_frame,
                text=timestamp,
                font=("Segoe UI", 8),
                bootstyle="secondary"
            ).pack(anchor=tk.W)

            # Probability
            ttk.Label(
                item_frame,
                text=f"{probability:.1%}",
                font=("Segoe UI", 9),
                bootstyle="danger" if is_phishing else "success"
            ).pack(side=tk.RIGHT)

            # Add separator
            if i < len(history) - 1 and i < 4:
                ttk.Separator(self.prev_results_frame).pack(fill=tk.X, pady=(0, 5))


if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingDetectorApp(root)
    root.mainloop()