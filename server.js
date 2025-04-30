const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const fs = require("fs");
const path = require('path');
const PDFDocument = require('pdfkit');
const crypto = require('crypto');
const multer = require('multer');
const { exec } = require('child_process');

const app = express();
const PORT = 3000;

// Store one-time passwords
const oneTimePasswords = new Map();

const USERS_FILE = path.join(__dirname, "users.json");
const BILLS_DIR = path.join(__dirname, "bills");
const ADMIN_FILE = path.join(__dirname, "admin.json");
const SUBJECTS_FILE = path.join(__dirname, "subjects.json");
const ITEMS_FILE = path.join(__dirname, "items.json");

// Initialize items file if it doesn't exist
if (!fs.existsSync(ITEMS_FILE)) {
    fs.writeFileSync(ITEMS_FILE, JSON.stringify([], null, 2));
}

// Load admin credentials from file
let adminCredentials;
try {
    adminCredentials = JSON.parse(fs.readFileSync(ADMIN_FILE, 'utf8'));
} catch (err) {
    // If file doesn't exist, create with default credentials
    adminCredentials = {
        email: "admin@study.com",
        password: "admin123"
    };
    fs.writeFileSync(ADMIN_FILE, JSON.stringify(adminCredentials, null, 2));
}

const ADMIN_EMAIL = adminCredentials.email;
let ADMIN_PASSWORD = adminCredentials.password;

// Ensure the bills directory exists
if (!fs.existsSync(BILLS_DIR)) {
    fs.mkdirSync(BILLS_DIR);
}

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Downloadable files configuration
const FILES_CONFIG = path.join(__dirname, "files-config.json");
let files = {};

try {
    files = JSON.parse(fs.readFileSync(FILES_CONFIG, 'utf8'));
} catch (err) {
    // Create empty config if doesn't exist
    fs.writeFileSync(FILES_CONFIG, JSON.stringify({}, null, 2));
}

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, 'files/'))
    },
    filename: (req, file, cb) => {
        // Keep original filename but remove spaces
        cb(null, file.originalname.replace(/\s+/g, '_'))
    }
});

const upload = multer({ storage: storage });

// Add this middleware after other middleware declarations
app.use((req, res, next) => {
    // Reload files configuration on each request
    try {
        const filesConfig = JSON.parse(fs.readFileSync(FILES_CONFIG, 'utf8'));
        files = filesConfig;
    } catch (err) {
        console.error('Error reloading files configuration:', err);
    }
    next();
});

// Function to load subjects
function loadSubjects() {
    try {
        return JSON.parse(fs.readFileSync(SUBJECTS_FILE, 'utf8'));
    } catch (err) {
        // Create empty subjects file if it doesn't exist
        fs.writeFileSync(SUBJECTS_FILE, JSON.stringify({}, null, 2));
        return {};
    }
}

// Function to restart server
function restartServer() {
    console.log('🔄 Restarting server...');
    exec('npm restart', (error, stdout, stderr) => {
        if (error) {
            console.error(`Error restarting server: ${error}`);
            return;
        }
        console.log(`✅ Server restarted successfully`);
    });
}

////////////////////////////////////////////////////////////////////////////////
// Password Verification & Download Endpoints
////////////////////////////////////////////////////////////////////////////////

app.post('/verify-password', (req, res) => {
    const { title, password, email } = req.body;
    const key = `${email}-${title}`;
    
    // Verify one-time password only
    if (oneTimePasswords.has(key) && oneTimePasswords.get(key) === password) {
        // Delete password after successful verification
        oneTimePasswords.delete(key);
        
        // Generate a unique download token
        const downloadToken = crypto.randomBytes(16).toString('hex');
        const tokenKey = `download-${downloadToken}`;
        oneTimePasswords.set(tokenKey, { email, title, expiry: Date.now() + 300000 }); // 5 minutes expiry
        
        res.json({ 
            success: true, 
            download: `/download/${encodeURIComponent(title)}?token=${downloadToken}` 
        });
    } else {
        res.json({ 
            success: false, 
            message: "Invalid or expired password. Please complete checkout to get a new password."
        });
    }
});

app.get('/download/:title', (req, res) => {
    const title = decodeURIComponent(req.params.title);
    const token = req.query.token;
    const tokenKey = `download-${token}`;

    if (!oneTimePasswords.has(tokenKey)) {
        return res.status(403).send("Download link expired or invalid");
    }

    const tokenData = oneTimePasswords.get(tokenKey);
    if (Date.now() > tokenData.expiry) {
        oneTimePasswords.delete(tokenKey);
        return res.status(403).send("Download link expired");
    }

    // Read the latest files configuration
    try {
        const filesConfig = JSON.parse(fs.readFileSync(FILES_CONFIG, 'utf8'));
        if (filesConfig[title]) {
            // Delete token after successful verification
            oneTimePasswords.delete(tokenKey);
            
            const filePath = path.join(__dirname, filesConfig[title].file);
            if (fs.existsSync(filePath)) {
                return res.download(filePath);
            }
        }
    } catch (err) {
        console.error('Error reading files configuration:', err);
    }

    res.status(404).send("File not found");
});

////////////////////////////////////////////////////////////////////////////////
// User Signup
////////////////////////////////////////////////////////////////////////////////

app.post("/signup", (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.json({ success: false, message: "All fields are required." });
    }

    fs.readFile(USERS_FILE, "utf-8", (err, data) => {
        if (err) return res.json({ success: false, message: "Server error." });

        let users = [];
        try {
            users = JSON.parse(data || "[]");
        } catch (parseErr) {
            return res.json({ success: false, message: "Corrupted user file." });
        }

        if (users.find(user => user.email === email)) {
            return res.json({ success: false, message: "Email already registered." });
        }

        const newUser = {
            name,
            email,
            password, // ⚠️ Plaintext. Use bcrypt in production!
            purchases: []
        };

        users.push(newUser);

        fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), err => {
            if (err) return res.json({ success: false, message: "Could not save user." });
            res.json({ success: true });
            // Restart server after successful signup
            restartServer();
        });
    });
});

////////////////////////////////////////////////////////////////////////////////
// User Login
////////////////////////////////////////////////////////////////////////////////

app.post("/login", (req, res) => {
    const { email, password, role } = req.body;

    // Admin login
    if (role === 'admin') {
        if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
            res.json({ 
                success: true, 
                user: { name: "Admin", email: ADMIN_EMAIL }
            });
        } else {
            res.json({ success: false, message: "Invalid admin credentials" });
        }
        return;
    }

    // Regular user login - prevent admin login as user
    if (email === ADMIN_EMAIL) {
        return res.json({ 
            success: false, 
            message: "Please use admin login for administrator account" 
        });
    }

    // Rest of the existing user login code...
    if (!email || !password) {
        return res.json({ success: false, message: "Both email and password are required." });
    }

    fs.readFile(USERS_FILE, "utf-8", (err, data) => {
        if (err) {
            console.error("Error reading users.json:", err);
            return res.status(500).json({ success: false, message: "Server error." });
        }

        let users = [];
        try {
            users = JSON.parse(data || "[]");
        } catch (parseErr) {
            console.error("Error parsing users.json:", parseErr);
            return res.status(500).json({ success: false, message: "Corrupted user data." });
        }

        const user = users.find(u => u.email === email && u.password === password);

        if (!user) {
            return res.json({ success: false, message: "Invalid email or password." });
        }

        const { password: pw, ...safeUser } = user;
        res.json({ success: true, user: safeUser });
    });
});

////////////////////////////////////////////////////////////////////////////////
// Record Purchase
////////////////////////////////////////////////////////////////////////////////

app.post("/record-purchase", (req, res) => {
    const { email, purchases } = req.body;

    fs.readFile(USERS_FILE, "utf-8", (err, data) => {
        if (err) return res.json({ success: false, message: "Server error." });

        const users = JSON.parse(data || "[]");
        const index = users.findIndex(u => u.email === email);

        if (index === -1) {
            return res.json({ success: false, message: "User not found." });
        }

        // Initialize purchases array if it doesn't exist
        users[index].purchases = users[index].purchases || [];
        // Add new purchases
        users[index].purchases.push(...purchases);

        fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), err => {
            if (err) return res.json({ success: false, message: "Failed to update purchase history." });

            const { password, ...safeUser } = users[index];
            res.json({ success: true, user: safeUser });
        });
    });
});

////////////////////////////////////////////////////////////////////////////////
// Checkout & Bill Generation
////////////////////////////////////////////////////////////////////////////////

app.post("/checkout", (req, res) => {
    const { email, cart } = req.body;

    if (!email || !cart || cart.length === 0) {
        return res.json({ success: false, message: "Invalid request. Email and cart are required." });
    }

    fs.readFile(USERS_FILE, "utf-8", (err, data) => {
        if (err) return res.status(500).json({ success: false, message: "Server error." });

        const users = JSON.parse(data || "[]");
        const user = users.find(u => u.email === email);

        if (!user) {
            return res.json({ success: false, message: "User not found." });
        }

        // Generate one-time passwords for purchased items
        const generatedPasswords = {};
        cart.forEach(item => {
            const otp = crypto.randomBytes(3).toString('hex'); // 6-character password
            const key = `${email}-${item.title}`;
            oneTimePasswords.set(key, otp);
            generatedPasswords[item.title] = otp;
        });

        // Calculate totals
        let subtotal = 0;
        cart.forEach(item => {
            subtotal += item.price * item.quantity;
        });
        const gst = 0.18 * subtotal;
        const total = subtotal + gst;

        // Generate PDF bill
        const doc = new PDFDocument({ margin: 50, size: 'A4' });
        const filePath = path.join(__dirname, `bills/${email}_bill_${Date.now()}.pdf`);
        const writeStream = fs.createWriteStream(filePath);
        doc.pipe(writeStream);

        // Add logo and header
        const logoPath = path.join(__dirname, "../frontend/LOGO.jpg");
        if (fs.existsSync(logoPath)) {
            doc.image(logoPath, 50, 45, { width: 80 });
        }

        // Header Section
        doc
            .fontSize(24)
            .font('Helvetica-Bold')
            .text('Study Materials Store', 180, 50, { align: 'right' })
            .fontSize(14)
            .font('Helvetica')
            .text('Invoice', 180, 80, { align: 'right' })
            .fontSize(10)
            .text('contact@studymaterials.com', 180, 100, { align: 'right' })
            .text('+91 123-456-7890', 180, 115, { align: 'right' });

        // Divider Line
        doc
            .lineWidth(1)
            .moveTo(50, 140)
            .lineTo(550, 140)
            .stroke('#333333');

        // Bill Details Section
        doc
            .fontSize(10)
            .font('Helvetica-Bold')
            .text('BILL TO', 50, 160)
            .font('Helvetica')
            .text(user.name, 50, 175)
            .text(user.email, 50, 190);

        // Invoice Details
        doc
            .fontSize(10)
            .font('Helvetica-Bold')
            .text('Invoice No:', 350, 160)
            .text('Date:', 350, 175)
            .text('Due Date:', 350, 190)
            .font('Helvetica')
            .text(`#${Date.now()}`, 420, 160)
            .text(new Date().toLocaleDateString('en-GB'), 420, 175)
            .text('Due on receipt', 420, 190);

        // Table Header
        const tableTop = 220;
        doc
            .lineWidth(0.5)
            .rect(50, tableTop - 15, 500, 25)
            .fill('#2C3E50')
            .fillColor('white')
            .fontSize(10)
            .font('Helvetica-Bold')
            .text('No', 60, tableTop - 10, { width: 30 })
            .text('Description', 100, tableTop - 10, { width: 180 })
            .text('Qty', 280, tableTop - 10, { width: 50, align: 'center' })
            .text('Price (Rs.)', 330, tableTop - 10, { width: 100, align: 'right' })
            .text('Amount (Rs.)', 430, tableTop - 10, { width: 100, align: 'right' });

        // Table Rows
        let yPos = tableTop + 20;
        doc.fillColor('black');

        cart.forEach((item, index) => {
            const totalItemPrice = item.price * item.quantity;
            
            if (index % 2 === 0) {
                doc
                    .rect(50, yPos - 10, 500, 20)
                    .fill('#F8F9FA');
            }

            doc
                .fillColor('black')
                .fontSize(9)
                .font('Helvetica')
                .text(index + 1, 60, yPos - 5, { width: 30 })
                .text(item.title, 100, yPos - 5, { width: 180 })
                .text(item.quantity.toString(), 280, yPos - 5, { width: 50, align: 'center' })
                .text(item.price.toFixed(2), 330, yPos - 5, { width: 100, align: 'right' })
                .text(totalItemPrice.toFixed(2), 430, yPos - 5, { width: 100, align: 'right' });

            yPos += 20;
        });

        // Totals Section
        const totalsY = yPos + 20;
        doc
            .font('Helvetica')
            .fontSize(10)
            .text('Subtotal:', 380, totalsY, { width: 90, align: 'right' })
            .text(`Rs. ${subtotal.toFixed(2)}`, 470, totalsY, { width: 80, align: 'right' })
            .text('GST (18%):', 380, totalsY + 20, { width: 90, align: 'right' })
            .text(`Rs. ${gst.toFixed(2)}`, 470, totalsY + 20, { width: 80, align: 'right' })
            .moveTo(380, totalsY + 45)
            .lineTo(550, totalsY + 45)
            .stroke()
            .font('Helvetica-Bold')
            .fontSize(11)
            .text('Total:', 380, totalsY + 55, { width: 90, align: 'right' })
            .text(`Rs. ${total.toFixed(2)}`, 470, totalsY + 55, { width: 80, align: 'right' });

        // Payment Information
        const paymentY = totalsY + 100;
        doc
            .rect(50, paymentY, 250, 70)
            .lineWidth(0.5)
            .stroke('#CCCCCC')
            .fontSize(10)
            .font('Helvetica-Bold')
            .text('Payment Information', 60, paymentY + 10)
            .font('Helvetica')
            .fontSize(9)
            .text('Bank Name: Study Materials Bank', 60, paymentY + 25)
            .text('Account No: 123-456-7890', 60, paymentY + 40)
            .text('IFSC Code: STDY0001234', 60, paymentY + 55);

        // Add password section to bill
        const passwordY = paymentY + 150;
        doc
            .font('Helvetica-Bold')
            .fontSize(10)
            .text('Your Download Passwords (One-Time Use Only)', 50, passwordY)
            .moveDown(0.5);

        Object.entries(generatedPasswords).forEach(([title, password], index) => {
            doc
                .font('Helvetica')
                .fontSize(9)
                .text(`${title}: ${password}`, 50, passwordY + 20 + (index * 15));
        });

        // Footer
        const bottomY = doc.page.height - 50;
        doc
            .fontSize(10)
            .font('Helvetica')
            .text('Thank you for your business!', 0, passwordY + 90, { align: 'center' })
            .moveDown(0.5)
            .fontSize(8)
            .text('Terms & Conditions Apply', 50, passwordY + 110)
            .text('Study Materials Store © 2025', 400, passwordY + 110);

        doc.end();

        writeStream.on("finish", () => {
            res.json({ 
                success: true, 
                download: `/download-bill/${path.basename(filePath)}`,
                passwords: generatedPasswords
            });
        });
    });
});

////////////////////////////////////////////////////////////////////////////////
// Bill Download Endpoint
////////////////////////////////////////////////////////////////////////////////

app.get("/download-bill/:filename", (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(__dirname, "bills", filename);

    if (fs.existsSync(filePath)) {
        res.download(filePath);
    } else {
        res.status(404).send("Bill not found.");
    }
});

////////////////////////////////////////////////////////////////////////////////
// Password Status Check
////////////////////////////////////////////////////////////////////////////////

app.post('/check-password-status', (req, res) => {
    const { email, title } = req.body;
    const key = `${email}-${title}`;
    
    res.json({ 
        hasPassword: oneTimePasswords.has(key),
        message: oneTimePasswords.has(key) ? 
            "Password available" : 
            "Password expired or not generated"
    });
});

////////////////////////////////////////////////////////////////////////////////
// Admin Endpoints
////////////////////////////////////////////////////////////////////////////////

app.get("/admin/users", (req, res) => {
    fs.readFile(USERS_FILE, "utf-8", (err, data) => {
        if (err) return res.status(500).json({ success: false });
        
        const users = JSON.parse(data || "[]");
        // Remove passwords before sending
        const safeUsers = users.map(({ password, ...user }) => user);
        res.json({ success: true, users: safeUsers });
    });
});

app.get("/admin/user-purchases/:email", (req, res) => {
    const userEmail = req.params.email;
    
    fs.readFile(USERS_FILE, "utf-8", (err, data) => {
        if (err) return res.status(500).json({ success: false });
        
        const users = JSON.parse(data || "[]");
        const user = users.find(u => u.email === userEmail);
        
        if (!user) return res.json({ success: false, message: "User not found" });
        
        res.json({ 
            success: true, 
            purchases: user.purchases || [] 
        });
    });
});

app.post("/change-password", (req, res) => {
    const { email, currentPassword, newPassword } = req.body;
    
    fs.readFile(USERS_FILE, "utf-8", (err, data) => {
        if (err) return res.status(500).json({ success: false });
        
        const users = JSON.parse(data || "[]");
        const userIndex = users.findIndex(u => u.email === email);
        
        if (userIndex === -1) {
            return res.json({ success: false, message: "User not found" });
        }
        
        if (users[userIndex].password !== currentPassword) {
            return res.json({ success: false, message: "Current password is incorrect" });
        }
        
        users[userIndex].password = newPassword;
        
        fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), err => {
            if (err) return res.json({ success: false, message: "Failed to update password" });
            res.json({ success: true });
        });
    });
});

app.post("/admin/change-password", (req, res) => {
    const { email, currentPassword, newPassword } = req.body;
    
    if (email !== ADMIN_EMAIL) {
        return res.json({ success: false, message: "Not authorized" });
    }
    
    if (currentPassword !== ADMIN_PASSWORD) {
        return res.json({ success: false, message: "Current password is incorrect" });
    }

    try {
        // Update memory
        ADMIN_PASSWORD = newPassword;
        
        // Update file
        adminCredentials.password = newPassword;
        fs.writeFileSync(ADMIN_FILE, JSON.stringify(adminCredentials, null, 2));
        
        res.json({ 
            success: true, 
            message: "Password updated successfully" 
        });
    } catch (err) {
        console.error('Error saving admin password:', err);
        res.json({ 
            success: false, 
            message: "Failed to update password permanently" 
        });
    }
});

app.get("/items", (req, res) => {
    try {
        const items = JSON.parse(fs.readFileSync(ITEMS_FILE, 'utf8'));
        res.json({ success: true, items });
    } catch (err) {
        console.error('Error reading items:', err);
        res.json({ success: false, message: "Failed to load items" });
    }
});

// Update the add-item endpoint to save to items.json instead of items.js
app.post("/admin/add-item", upload.single('file'), (req, res) => {
    const { title, desc, price, subject, newSubjectCode, newSubjectName } = req.body;
    const file = req.file;
    
    try {
        // Handle new subject if provided
        if (newSubjectCode && newSubjectName) {
            const subjects = loadSubjects();
            const subjectKey = newSubjectCode.toLowerCase().replace(/\s+/g, '_');
            subjects[subjectKey] = `${newSubjectCode} - ${newSubjectName}`;
            fs.writeFileSync(SUBJECTS_FILE, JSON.stringify(subjects, null, 2));
        }

        // Read current items
        let items = [];
        if (fs.existsSync(ITEMS_FILE)) {
            items = JSON.parse(fs.readFileSync(ITEMS_FILE, 'utf8'));
        }
        
        // Add new item
        const newItem = { 
            title, 
            desc, 
            price: Number(price), 
            subject,
            filename: file ? file.filename : null
        };
        
        items.push(newItem);
        
        // Save items
        fs.writeFileSync(ITEMS_FILE, JSON.stringify(items, null, 2));

        // Update files configuration
        if (file) {
            const filesConfigPath = path.join(__dirname, 'files-config.json');
            let filesConfig = {};
            
            try {
                filesConfig = JSON.parse(fs.readFileSync(filesConfigPath, 'utf8'));
            } catch (err) {
                console.log('Creating new files-config.json');
            }

            // Add file entry with proper file path
            filesConfig[title] = {
                file: `files/${file.filename}`
            };

            // Write updated config
            fs.writeFileSync(filesConfigPath, JSON.stringify(filesConfig, null, 2));
        }

        res.json({ success: true });

        // Restart server with delay
        setTimeout(() => {
            // Update in-memory files configuration
            try {
                files = JSON.parse(fs.readFileSync(FILES_CONFIG, 'utf8'));
                console.log('Files configuration reloaded successfully');
            } catch (err) {
                console.error('Error reloading files configuration:', err);
            }
        }, 1000);

    } catch (err) {
        console.error('Error managing items:', err);
        res.json({ success: false, message: "Failed to add item" });
    }
});

// Update the remove-item endpoint
app.delete("/admin/remove-item/:index", (req, res) => {
    const index = parseInt(req.params.index);

    try {
        // Read current items
        let items = JSON.parse(fs.readFileSync(ITEMS_FILE, 'utf8'));

        // Get the item to be removed
        const itemToRemove = items[index];

        // Remove item from items array
        items.splice(index, 1);

        // Save updated items
        fs.writeFileSync(ITEMS_FILE, JSON.stringify(items, null, 2));

        // Clean up files-config.json if no other item uses the same file
        const filesConfigPath = path.join(__dirname, 'files-config.json');
        let filesConfig = JSON.parse(fs.readFileSync(filesConfigPath, 'utf8'));

        let fileDeleted = false;
        if (itemToRemove && itemToRemove.filename) {
            // Check if any other item uses this file
            const stillUsed = items.some(it => it.filename === itemToRemove.filename);
            if (!stillUsed) {
                // Remove file entry from files-config.json
                delete filesConfig[itemToRemove.title];
                fs.writeFileSync(filesConfigPath, JSON.stringify(filesConfig, null, 2));

                // Delete the file from disk
                const filePath = path.join(__dirname, 'files', itemToRemove.filename);
                if (fs.existsSync(filePath)) {
                    fs.unlinkSync(filePath);
                    fileDeleted = true;
                }
            } else {
                // Only remove the entry for this title
                delete filesConfig[itemToRemove.title];
                fs.writeFileSync(filesConfigPath, JSON.stringify(filesConfig, null, 2));
            }
        }

        res.json({ 
            success: true, 
            message: fileDeleted 
                ? "Item and associated file deleted successfully." 
                : "Item deleted successfully." 
        });

    } catch (err) {
        console.error('Error managing items:', err);
        res.json({ success: false, message: "Failed to remove item" });
    }
});

app.get('/subjects', (req, res) => {
    const subjects = loadSubjects();
    res.json({ success: true, subjects });
});

app.post('/admin/add-subject', (req, res) => {
    const { code, name } = req.body;
    const subjectKey = code.toLowerCase().replace(/\s+/g, '_');
    const displayName = `${code} - ${name}`;

    const subjects = loadSubjects();
    subjects[subjectKey] = displayName;

    fs.writeFileSync(SUBJECTS_FILE, JSON.stringify(subjects, null, 2));
    res.json({ success: true, subjects });
});

////////////////////////////////////////////////////////////////////////////////
// Start Server
////////////////////////////////////////////////////////////////////////////////

app.listen(PORT, () => {
    console.log(`✅ Server running at http://localhost:${PORT}`);
});