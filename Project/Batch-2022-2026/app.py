from flask import Flask, render_template, request, redirect, url_for, session, send_file
from config import Config
from database.models import db, User, Analysis

from detector.analyzer import analyze_input
from detector.risk_engine import calculate_risk
from detector.process_monitor import scan_processes

from utils.auth import hash_password, verify_password
from utils.blockchain_ledger import add_record
from utils.pdf_report import generate_pdf
from utils.alert_simulator import soc_alert

import os


app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)


# ---------- Initialize Database ----------
with app.app_context():

    db.create_all()

    if not User.query.first():
        admin = User(username="admin", password=hash_password("admin123"))
        db.session.add(admin)
        db.session.commit()


# ---------- LOGIN ----------
@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and verify_password(user.password, password):

            session["user"] = username

            return redirect("/dashboard")

    return render_template("login.html")


# ---------- LOGOUT ----------
@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


# ---------- DASHBOARD ----------
@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/")

    records = Analysis.query.all()

    total = len(records)

    high = sum(1 for r in records if r.risk in ["High", "Critical"])
    medium = sum(1 for r in records if r.risk == "Medium")
    low = sum(1 for r in records if r.risk == "Low")

    return render_template(
        "dashboard.html",
        total=total,
        high=high,
        medium=medium,
        low=low
    )


# ---------- ANALYZE ----------
@app.route("/analyze", methods=["GET", "POST"])
def analyze():

    if "user" not in session:
        return redirect("/")

    if request.method == "POST":

        text = request.form.get("text_input", "")

        if "file" in request.files:

            f = request.files["file"]

            if f.filename != "":
                path = os.path.join("uploads", f.filename)
                f.save(path)

                with open(path, "r", errors="ignore") as file:
                    text = file.read()

        findings = analyze_input(text)

        risk = calculate_risk(findings)

        ledger_hash = add_record(str(findings) + risk)

        record = Analysis(
            content=text[:500],
            findings=str(findings),
            risk=risk,
            ledger_hash=ledger_hash
        )

        db.session.add(record)
        db.session.commit()

        if risk in ["High", "Critical"]:
            soc_alert("Possible ransomware behaviour detected")

        return redirect(url_for("results", id=record.id))

    return render_template("analyze.html")


# ---------- RESULTS ----------
@app.route("/results/<int:id>")
def results(id):

    if "user" not in session:
        return redirect("/")

    rec = Analysis.query.get_or_404(id)

    return render_template("results.html", rec=rec)


# ---------- HISTORY ----------
@app.route("/history")
def history():

    if "user" not in session:
        return redirect("/")

    records = Analysis.query.order_by(Analysis.id.desc()).all()

    return render_template("history.html", records=records)


# ---------- PROCESS MONITOR ----------
@app.route("/monitor")
def monitor():

    if "user" not in session:
        return redirect("/")

    processes = scan_processes()

    return render_template("monitor.html", processes=processes)


# ---------- ATTACK SIMULATION ----------
@app.route("/simulate", methods=["GET", "POST"])
def simulate():

    if "user" not in session:
        return redirect("/")

    if request.method == "POST":

        sample = """
        encrypt files
        rename .locked
        vssadmin delete shadows
        reg add HKCU
        """

        findings = analyze_input(sample)

        risk = calculate_risk(findings)

        soc_alert("Simulated ransomware activity")

        return redirect("/dashboard")

    return render_template("simulator.html")


# ---------- THREAT HUNT ----------
@app.route("/hunt")
def hunt():

    if "user" not in session:
        return redirect("/")

    q = request.args.get("q")

    results = []

    if q:
        results = Analysis.query.filter(
            Analysis.findings.contains(q)
        ).all()

    return render_template("threat_hunt.html", results=results)


# ---------- PDF REPORT ----------
@app.route("/report/<int:id>")
def report(id):

    if "user" not in session:
        return redirect("/")

    rec = Analysis.query.get_or_404(id)

    path = generate_pdf(rec)

    return send_file(path, as_attachment=True)


# ---------- RUN SERVER ----------
if __name__ == "__main__":
    app.run(debug=True)