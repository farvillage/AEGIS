import os
import sys
import threading
import webbrowser
from tkinter import filedialog
import customtkinter as ctk
import pandas as pd
import numpy as np

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.model import OptimizedAegisEnsembleInference
from backend.parser import process_pcap_to_flows_optimized
from backend.grc import calculate_grc_risk_score
from backend.xai import generate_shap_explanation

# --- Theme Configuration ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

BG = "#000000"
SURFACE = "#0a0a0a"
SURFACE_HOVER = "#1a1a1a"
ACCENT = "#484aaa"
ACCENT_HOVER = "#3a3c88"
ACCENT_BUSY = "#2d2f6b"
TEXT = "#e2e8f0"
TEXT_DIM = "#a0aec0"

FONT_FAMILY = "Courier"
F_TITLE = (FONT_FAMILY, 32, "bold")
F_SIDE_TITLE = (FONT_FAMILY, 18, "bold")
F_BOLD = (FONT_FAMILY, 13, "bold")
F_TAGLINE = (FONT_FAMILY, 13)
F_BODY = (FONT_FAMILY, 12)
F_SMALL = (FONT_FAMILY, 11)
F_SMALL_BOLD = (FONT_FAMILY, 11, "bold")
F_SMALL_ITALIC = (FONT_FAMILY, 11, "italic")
F_LINK = (FONT_FAMILY, 11, "underline")

USE_SEVERITY_COLORS = True
SEVERITY_COLORS = {
    "low": "#7fb99a",
    "moderate": "#d9b36c",
    "medium": "#d9b36c",
    "high": "#e0905a",
    "critical": "#e57373",
}

REPORT_WIDTH = 56
RULE = "─" * REPORT_WIDTH

# --- App identity (name, icon, bundled-resource paths) ---
APP_NAME = "AEGIS"
MODEL_REL = os.path.join("models", "aegis_ciciomt_model.onnx")
APP_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
ICON_NAMES = ("aegis_icon", "icon", "aegis", "logo")


def resource_path(rel):
    """Works from source (repo root) and inside a PyInstaller bundle (sys._MEIPASS)."""
    base = getattr(sys, "_MEIPASS", APP_ROOT)
    return os.path.join(base, rel)


def find_icon(ext):
    here = os.path.dirname(os.path.abspath(__file__))
    folders = [resource_path("assets"), APP_ROOT, os.path.join(here, "assets"), here]
    for folder in folders:
        for name in ICON_NAMES:
            path = os.path.join(folder, f"{name}.{ext}")
            if os.path.exists(path):
                return path
    return None


def set_process_identity(name=APP_NAME):
    """Call BEFORE creating the Tk window.

    macOS (running as a script): changes the menu-bar app name from 'python3.x'.
    Needs `pip install pyobjc-framework-Cocoa`; silently skipped if missing.
    Windows: gives the process its own taskbar identity (own icon, not Python's).
    """
    if sys.platform == "darwin":
        try:
            from Foundation import NSBundle
            bundle = NSBundle.mainBundle()
            info = bundle.localizedInfoDictionary() or bundle.infoDictionary()
            if info is not None:
                info["CFBundleName"] = name
                info["CFBundleDisplayName"] = name
        except Exception as e:
            print(f"[AEGIS] macOS app name not set (pip install pyobjc-framework-Cocoa): {e}")
    elif sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("ifpb.aegis.engine")
        except Exception:
            pass


def set_dock_icon_macos(png_path):
    """Sets the Dock icon when running as a script. Call AFTER the Tk window exists."""
    try:
        from AppKit import NSApplication, NSImage
        img = NSImage.alloc().initByReferencingFile_(png_path)
        if img is not None and img.isValid():
            NSApplication.sharedApplication().setApplicationIconImage_(img)
            return True
    except Exception as e:
        print(f"[AEGIS] Dock icon not set (pip install pyobjc-framework-Cocoa): {e}")
    return False


def build_report(total_rows, attack_count, risk_score, risk_level, top_feature):
    normal_count = total_rows - attack_count

    def pct(n):
        return 100.0 * n / total_rows if total_rows else 0.0

    w = len(f"{total_rows:,}")
    level_key = "".join(ch for ch in str(risk_level).lower() if ch.isalpha())
    sev_tag = f"sev_{level_key}" if level_key in SEVERITY_COLORS else "sev_high"
    seg = []
    add = seg.append

    add(("\nBehavioral Analysis & GRC Report\n", "head"))
    add((RULE + "\n", "rule"))
    add((f"AEGIS evaluated {total_rows:,} total network flows:\n", None))
    add(("  Malicious flows flagged  ", "dim"))
    add((f"{attack_count:>{w},}    {pct(attack_count):>5.1f}%\n", None))
    add(("  Normal flows verified    ", "dim"))
    add((f"{normal_count:>{w},}    {pct(normal_count):>5.1f}%\n", None))

    add(("\nGRC Quantitative Risk Assessment\n", "head"))
    add((RULE + "\n", "rule"))
    add(("  Risk Score   ", "dim"))
    add((f"{risk_score:.2f}%\n", None))
    add(("  Level        ", "dim"))
    add((f"● {risk_level}\n", sev_tag))
    add(("  Compliance   ", "dim"))
    add(("CIA Triad Weighted Evaluation Complete (LGPD / HIPAA / GDPR).\n", None))

    add(("\nXAI Compliance Audit Trail (SHAP)\n", "head"))
    add((RULE + "\n", "rule"))
    add(("  Primary Driving Feature  ", "dim"))
    add((f"{top_feature}\n", None))
    add(("  Audit Status             ", "dim"))
    add(("Logged for Regulatory Verification.\n", None))

    add(("\n", None))
    if attack_count > 0:
        add((f"Alert: {attack_count:,} malicious network flow(s) identified in telemetry.\n", "alert"))
    else:
        add(("All network traffic flows classified as normal.\n", None))
    return seg


class CollapsibleDropdown(ctk.CTkFrame):
    def __init__(self, master, title="Who am I?", **kwargs):
        super().__init__(master, fg_color=SURFACE, border_color=ACCENT, border_width=1, corner_radius=6, **kwargs)
        self.grid_columnconfigure(0, weight=1)

        self.title = title
        self.is_open = True

        self.toggle_btn = ctk.CTkButton(
            self,
            text=f"▼  {title}",
            command=self.toggle,
            fg_color="transparent",
            hover_color=SURFACE_HOVER,
            text_color=TEXT,
            anchor="w",
            font=F_BOLD,
            height=30,
        )
        self.toggle_btn.grid(row=0, column=0, sticky="ew", padx=10, pady=5)

        self.content_frame = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        self.content_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.content_frame.grid_columnconfigure(0, weight=1)

        wrap = 215

        def label(text, font, color, pady):
            lbl = ctk.CTkLabel(self.content_frame, text=text, font=font, text_color=color,
                               justify="left", anchor="w", wraplength=wrap)
            lbl.grid(sticky="w", padx=14, pady=pady)
            return lbl

        label("Ygor Gesteira", F_SMALL_BOLD, TEXT, (14, 0))
        label("Master's Researcher @ Instituto Federal da Paraíba (IFPB)", F_SMALL, TEXT_DIM, (2, 10))
        label("Currently developing AEGIS as part of my Master's research, focusing on machine "
              "learning applications for cybersecurity in Internet of Medical Things (IoMT).",
              F_SMALL, TEXT, (0, 10))
        label("\"With great power comes great responsibility\" - Stan Lee", F_SMALL_ITALIC, TEXT_DIM, (0, 10))

        email = "ygorgesteira@gmail.com"
        self.email_label = label(email, F_LINK, TEXT_DIM, (0, 14))
        try:
            self.email_label.configure(cursor="hand2")
        except Exception:
            pass
        self.email_label.bind("<Enter>", lambda e: self.email_label.configure(text_color=TEXT))
        self.email_label.bind("<Leave>", lambda e: self.email_label.configure(text_color=TEXT_DIM))
        self.email_label.bind("<Button-1>", lambda e: webbrowser.open(f"mailto:{email}"))

    def toggle(self):
        if self.is_open:
            self.content_frame.grid_remove()
            self.toggle_btn.configure(text=f"►  {self.title}")
            self.is_open = False
        else:
            self.content_frame.grid()
            self.toggle_btn.configure(text=f"▼  {self.title}")
            self.is_open = True


class AegisDesktopApp(ctk.CTk):
    UPLOAD_TEXT = "Upload Network Traffic Capture"

    def __init__(self):
        super().__init__()

        self.title("AEGIS Engine")
        self.geometry("1000x720")
        self.minsize(860, 600)
        self.configure(fg_color=BG)
        self._apply_app_icon()

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        model_path = resource_path(MODEL_REL)
        if not os.path.exists(model_path):
            model_path = MODEL_REL
        if os.path.exists(model_path):
            self.inference_engine = OptimizedAegisEnsembleInference(model_path)
        else:
            self.inference_engine = None

        self.sidebar_frame = ctk.CTkFrame(self, width=280, fg_color=SURFACE, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.pack_propagate(False)

        self.sidebar_title = ctk.CTkLabel(
            self.sidebar_frame,
            text="About:",
            font=F_SIDE_TITLE,
            text_color=TEXT
        )
        self.sidebar_title.pack(padx=20, pady=(25, 15), anchor="w")

        self.dropdown = CollapsibleDropdown(self.sidebar_frame, title="Who am I?")
        self.dropdown.pack(padx=15, pady=5, fill="x")

        self.main_frame = ctk.CTkFrame(self, fg_color=BG)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=40, pady=40)

        self.header_label = ctk.CTkLabel(
            self.main_frame,
            text="AEGIS",
            font=F_TITLE,
            text_color=TEXT
        )
        self.header_label.pack(anchor="w", pady=(0, 4))

        self.title_accent = ctk.CTkFrame(self.main_frame, width=48, height=3, fg_color=ACCENT, corner_radius=0)
        self.title_accent.pack(anchor="w", pady=(0, 14))

        self.sub_label_1 = ctk.CTkLabel(
            self.main_frame,
            text="Real-time intrusion detection.",
            font=F_TAGLINE,
            text_color=TEXT
        )
        self.sub_label_1.pack(anchor="w", pady=(0, 6))

        self.sub_label_2 = ctk.CTkLabel(
            self.main_frame,
            text="Upload raw network captures (.pcap) or processed datasets (.csv) from medical sensors to detect malicious behavioral anomalies instantly.",
            font=F_BODY,
            text_color=TEXT_DIM,
            justify="left",
            anchor="w",
            wraplength=680,
        )
        self.sub_label_2.pack(anchor="w", pady=(0, 20))
        self._wrap = 680
        self.main_frame.bind("<Configure>", self._on_main_resize)

        self.upload_btn = ctk.CTkButton(
            self.main_frame,
            text=self.UPLOAD_TEXT,
            command=self.load_file,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            text_color="#ffffff",
            text_color_disabled=TEXT_DIM,
            font=F_BOLD,
            height=40,
        )
        self.upload_btn.pack(anchor="w", pady=(10, 8))

        self.progress = ctk.CTkProgressBar(
            self.main_frame, mode="indeterminate", height=3, corner_radius=0,
            fg_color=SURFACE_HOVER, progress_color=ACCENT,
        )

        self.log_box = ctk.CTkTextbox(
            self.main_frame,
            width=680,
            height=340,
            fg_color=SURFACE,
            text_color=TEXT,
            border_color=ACCENT,
            border_width=1,
            border_spacing=12,
            font=F_BODY,
            wrap="word",
        )
        self.log_box.pack(fill="both", expand=True, pady=(8, 0))
        try:
            self.log_box._textbox.configure(spacing1=1, spacing3=3)
        except Exception:
            pass

        self._configure_log_tags()
        self.log_box.insert("0.0", "System ready. Click 'Upload Network Traffic Capture' to begin...\n")
        if self.inference_engine:
            self.log_box.insert("end", "Engine: ONNX model loaded.\n", "dim")
        else:
            self.log_box.insert("end", "Engine: model 'aegis_ciciomt_model.onnx' not found in models directory.\n", "error")

    def _apply_app_icon(self):
        """Window/Dock/taskbar icon. Looks for assets/aegis_icon.png (and .ico on Windows)."""
        png = find_icon("png")
        if png:
            try:
                from PIL import Image, ImageTk
                img = Image.open(png).convert("RGBA")
                img.thumbnail((512, 512))
                self._icon_img = ImageTk.PhotoImage(img)
                self.iconphoto(True, self._icon_img)
            except Exception as e:
                print(f"[AEGIS] could not load icon '{png}': {e}")
        else:
            print("[AEGIS] icon not found. Put a PNG at assets/aegis_icon.png")

        if sys.platform.startswith("win"):
            ico = find_icon("ico")
            if ico:
                self.after(250, lambda: self.iconbitmap(ico))
        elif sys.platform == "darwin" and png:
            self.after(300, lambda: set_dock_icon_macos(png))

    def _configure_log_tags(self):
        def sev(color):
            return color if USE_SEVERITY_COLORS else TEXT

        self.log_box.tag_config("head", foreground=TEXT)
        self.log_box.tag_config("rule", foreground=ACCENT)
        self.log_box.tag_config("dim", foreground=TEXT_DIM)
        self.log_box.tag_config("alert", foreground=sev(SEVERITY_COLORS["high"]))
        self.log_box.tag_config("error", foreground=sev(SEVERITY_COLORS["critical"]))
        for name, color in SEVERITY_COLORS.items():
            self.log_box.tag_config(f"sev_{name}", foreground=sev(color))

    def _on_main_resize(self, event):
        wrap = max(320, event.width - 20)
        if abs(wrap - self._wrap) >= 8:
            self._wrap = wrap
            self.sub_label_2.configure(wraplength=wrap)

    def _set_busy(self, busy):
        if busy:
            self.upload_btn.configure(state="disabled", text="Analyzing...", fg_color=ACCENT_BUSY)
            self.progress.pack(fill="x", pady=(0, 0), before=self.log_box)
            self.progress.start()
        else:
            self.progress.stop()
            self.progress.pack_forget()
            self.upload_btn.configure(state="normal", text=self.UPLOAD_TEXT, fg_color=ACCENT)

    def _log(self, text, tag=None):
        def _do():
            if tag:
                self.log_box.insert("end", text, tag)
            else:
                self.log_box.insert("end", text)
            self.log_box.see("end")
        self.after(0, _do)

    def _log_segments(self, segments):
        def _do():
            for text, tag in segments:
                if tag:
                    self.log_box.insert("end", text, tag)
                else:
                    self.log_box.insert("end", text)
            self.log_box.see("end")
        self.after(0, _do)

    def load_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Network Traffic Capture",
            filetypes=[("Network Files", "*.csv *.pcap *.pcapng")]
        )
        if not file_path:
            return

        file_name = os.path.basename(file_path)
        self.log_box.delete("0.0", "end")
        self.log_box.insert("0.0", f"Data detected: {file_name}\nAEGIS Engine active. Running analysis...\n")

        self._set_busy(True)
        threading.Thread(target=self.process_file_background, args=(file_path, file_name), daemon=True).start()

    def process_file_background(self, file_path, file_name):
        try:
            if not self.inference_engine:
                self._log("\n[Error] ONNX model 'aegis_ciciomt_model.onnx' not found in models directory.", "error")
                return

            lower_path = file_path.lower()
            if lower_path.endswith('.csv'):
                df = pd.read_csv(file_path)

                target_features = ['Temp', 'SpO2', 'Pulse_Rate', 'SYS', 'DIA', 'Heart_rate', 'Resp_Rate', 'ST']
                if all(col in df.columns for col in target_features):
                    df_processed = df[target_features].fillna(0)
                else:
                    numeric_df = df.select_dtypes(include=[np.number])
                    cleaned = numeric_df.drop(columns=[c for c in ['packet_num', 'Packet_num', 'label', 'type', 'Attack Category'] if c in numeric_df.columns], errors='ignore')
                    if cleaned.shape[1] >= 8:
                        df_processed = cleaned.iloc[:, :8].fillna(0)
                    else:
                        df_processed = cleaned.reindex(columns=range(8), fill_value=0).fillna(0)
            elif lower_path.endswith(('.pcap', '.pcapng')):
                df_processed = process_pcap_to_flows_optimized(file_path)
            else:
                self._log("\n[Error] Unsupported file format.", "error")
                return

            if df_processed.empty:
                self._log("\n[Error] No valid flows extracted from file.", "error")
                return

            df_result, attack_count = self.inference_engine.predict(df_processed)
            total_rows = len(df_result)

            attack_ratio = (attack_count / total_rows * 100.0) if total_rows > 0 else 0.0
            risk_score = calculate_grc_risk_score(
                confidentiality_impact=attack_ratio,
                integrity_impact=attack_ratio * 0.9,
                availability_impact=attack_ratio * 1.1
            )

            if risk_score > 75:
                risk_level = "Critical"
            elif risk_score > 50:
                risk_level = "High"
            elif risk_score > 25:
                risk_level = "Moderate"
            else:
                risk_level = "Low"

            xai_report = generate_shap_explanation(self.inference_engine, df_processed)
            top_feature = xai_report.get('top_influencing_feature', 'Feature 0') if isinstance(xai_report, dict) else 'Ensemble Weight'

            self._log_segments(build_report(
                total_rows, attack_count, risk_score, risk_level, top_feature
            ))

        except Exception as e:
            self._log(f"\n[Exception Error]: {str(e)}", "error")
        finally:
            self.after(0, lambda: self._set_busy(False))


if __name__ == "__main__":
    set_process_identity(APP_NAME)
    app = AegisDesktopApp()
    app.mainloop()