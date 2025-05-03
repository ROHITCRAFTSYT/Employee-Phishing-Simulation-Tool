# Phishsim: Employee Phishing Simulation Tool

Phishsim is a comprehensive phishing simulation platform designed to strengthen your organization's security posture through education and awareness. This tool allows security teams to create realistic phishing campaigns, track employee responses, and provide targeted training to build resilience against social engineering attacks.

## 🛡️ Features

- **Campaign Management**: Create, schedule, and manage phishing campaigns
- **Email Templates**: Build custom phishing templates with varying difficulty levels
- **Tracking & Analytics**: Monitor open rates, click rates, and reporting rates
- **Educational Training**: Automatically redirect users who click links to relevant training
- **Detailed Reporting**: Generate comprehensive reports with actionable insights
- **Department Analysis**: Compare security awareness across different departments
- **Employee Risk Profiles**: Identify vulnerable employees who may need additional training
- **Multi-level Security**: Role-based access control with admin features

## 📋 Prerequisites

- Python 3.8+
- Flask and associated extensions
- SMTP server access for sending emails
- SQLite (default) or other database

## 🚀 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/rohitcraftsyt/phishsim.git
   cd phishsim
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure environment variables:
   ```bash
   export SECRET_KEY="your-secure-secret-key"
   export SMTP_SERVER="smtp.example.com"
   export SMTP_PORT="587"
   export SMTP_USERNAME="your-email@example.com"
   export SMTP_PASSWORD="your-password"
   ```
   
   For Windows:
   ```cmd
   set SECRET_KEY=your-secure-secret-key
   set SMTP_SERVER=smtp.example.com
   set SMTP_PORT=587
   set SMTP_USERNAME=your-email@example.com
   set SMTP_PASSWORD=your-password
   ```

5. Run the application:
   ```bash
   python app.py
   ```

6. Navigate to `http://localhost:5000` and follow the installation wizard to create your admin account.

## 🐋 Docker Deployment

```bash
# Build the Docker image
docker build -t phishsim .

# Run the container
docker run -d -p 5000:5000 \
  -e SECRET_KEY="your-secure-secret-key" \
  -e SMTP_SERVER="smtp.example.com" \
  -e SMTP_PORT="587" \
  -e SMTP_USERNAME="your-email@example.com" \
  -e SMTP_PASSWORD="your-password" \
  -v phishsim-data:/app/instance \
  --name phishsim \
  phishsim
```

## 🔧 Configuration

Phishsim can be configured through environment variables or by updating the settings in the admin interface after installation.

### Key Settings:

- **SMTP Configuration**: Required for sending phishing emails
- **Database Path**: Default is SQLite in the instance folder
- **Secret Key**: Used for session security
- **Debug Mode**: Enable for development only

## 💻 Usage

### 1. Setting Up Employees

- Import employees via CSV or add them manually
- Organize employees by department for targeted campaigns

### 2. Creating Email Templates

- Design realistic phishing templates
- Use placeholders like `{FIRST_NAME}` and `{TRACKING_LINK}`
- Set difficulty levels based on how obvious the phishing indicators are

### 3. Running Campaigns

- Select target employees
- Choose an email template
- Schedule the campaign launch
- Monitor results in real-time

### 4. Analyzing Results

- View comprehensive metrics
- Generate reports by department, campaign, or time period
- Identify trends and improvement areas

### 5. Training Integration

- Create custom training modules
- Automatically assign training to employees who click on phishing links
- Track training completion rates

## 📊 Sample Workflow

1. Create a template mimicking a password reset email
2. Select employees from the Finance department
3. Schedule the campaign for Monday morning
4. Monitor who opens, clicks, or reports the email
5. Review results and identify training opportunities
6. Generate reports to demonstrate security improvements

## 🔒 Security Note

phishsim is designed for legitimate security training only. Using this tool for malicious purposes is against the terms of use and may be illegal. Always ensure you have proper authorization before conducting phishing simulations.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Made with ❤️ for cybersecurity education
