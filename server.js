const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" }
}));
app.use(cors({
    origin: 'http://localhost:5500', // Change this to your frontend port
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = ['.pdf', '.docx', '.txt', '.text'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
        cb(null, true);
    } else {
        cb(new Error('Invalid file type. Only PDF, DOCX, and TXT files are allowed.'));
    }
};

const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit
    }
});

// In-memory user storage (replace with database in production)
const users = [];
const analysisHistory = [];

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Helper function to extract text from different file types
async function extractTextFromFile(filePath, mimeType) {
    const ext = path.extname(filePath).toLowerCase();
    
    try {
        if (ext === '.pdf') {
            const dataBuffer = fs.readFileSync(filePath);
            const data = await pdfParse(dataBuffer);
            return data.text;
        } else if (ext === '.docx') {
            const result = await mammoth.extractRawText({ path: filePath });
            return result.value;
        } else if (ext === '.txt' || ext === '.text') {
            return fs.readFileSync(filePath, 'utf8');
        } else {
            throw new Error('Unsupported file type');
        }
    } catch (error) {
        console.error('Error extracting text:', error);
        throw error;
    }
}

// Routes

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// User registration
app.post('/api/register', [
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { name, email, password } = req.body;
        
        // Check if user already exists
        if (users.find(u => u.email === email)) {
            return res.status(400).json({ error: 'User already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const user = {
            id: users.length + 1,
            name,
            email,
            password: hashedPassword,
            createdAt: new Date().toISOString()
        };
        
        users.push(user);
        
        // Generate JWT token
        const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, {
            expiresIn: '24h'
        });
        
        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

// User login
app.post('/api/login', [
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { email, password } = req.body;
        
        // Find user
        const user = users.find(u => u.email === email);
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, {
            expiresIn: '24h'
        });

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Failed to login' });
    }
});

// Upload and analyze thesis
app.post('/api/analyze', authenticateToken, upload.single('thesis'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        // Extract text from file
        const text = await extractTextFromFile(req.file.path, req.file.mimetype);
        
        // Analyze the thesis
        const analysis = analyzeThesis(text, req.file.originalname);
        
        // Save analysis to history
        const historyEntry = {
            id: analysisHistory.length + 1,
            userId: req.user.id,
            fileName: req.file.originalname,
            analysis: analysis,
            timestamp: new Date().toISOString()
        };
        analysisHistory.push(historyEntry);
        
        // Clean up uploaded file (optional - uncomment to delete after analysis)
        // fs.unlinkSync(req.file.path);
        
        res.json({
            message: 'Analysis complete',
            fileName: req.file.originalname,
            analysis: analysis
        });
    } catch (error) {
        console.error('Analysis error:', error);
        res.status(500).json({ error: 'Failed to analyze thesis' });
    }
});

// Analyze thesis text (simplified academic analysis)
function analyzeThesis(text, fileName) {
    const wordCount = text.split(/\s+/).length;
    const charCount = text.length;
    const sentenceCount = text.split(/[.!?]+/).length;
    const paragraphCount = text.split(/\n\s*\n/).length;
    
    // Extract sections based on common headers
    const sections = {
        abstract: extractSection(text, ['abstract', 'summary']),
        introduction: extractSection(text, ['introduction', 'background']),
        methodology: extractSection(text, ['methodology', 'methods', 'approach']),
        results: extractSection(text, ['results', 'findings']),
        discussion: extractSection(text, ['discussion']),
        conclusion: extractSection(text, ['conclusion', 'conclusions'])
    };
    
    // Calculate scores
    const scores = {
        overall: calculateOverallScore(text, sections),
        clarity: calculateClarityScore(text),
        structure: calculateStructureScore(text, sections),
        citations: calculateCitationsScore(text),
        grammar: calculateGrammarScore(text),
        methodology: calculateMethodologyScore(text, sections.methodology),
        results: calculateResultsScore(text, sections.results)
    };
    
    // Generate section feedback
    const sectionFeedback = {};
    Object.keys(sections).forEach(key => {
        if (sections[key]) {
            sectionFeedback[key] = generateSectionFeedback(key, sections[key]);
        }
    });
    
    // Citation analysis
    const citations = extractCitations(text);
    
    // Related papers
    const relatedPapers = generateRelatedPapers(text);
    
    // Plagiarism analysis (simplified for demo)
    const plagiarismAnalysis = performPlagiarismAnalysis(text);
    
    return {
        fileName,
        fileInfo: {
            wordCount,
            charCount,
            sentenceCount,
            paragraphCount,
            estimatedReadTime: Math.ceil(wordCount / 200)
        },
        sections: sections,
        sectionFeedback: sectionFeedback,
        scores: scores,
        citations: citations,
        relatedPapers: relatedPapers,
        plagiarism: plagiarismAnalysis,
        recommendations: generateRecommendations(scores),
        strengths: identifyStrengths(scores, sections),
        weaknesses: identifyWeaknesses(scores, sections),
        keywords: extractKeywords(text, 10)
    };
}

// Helper functions for analysis
function extractSection(text, keywords) {
    const lowerText = text.toLowerCase();
    for (const keyword of keywords) {
        const index = lowerText.indexOf(keyword);
        if (index !== -1) {
            // Extract a reasonable chunk around the keyword
            const start = Math.max(0, index - 100);
            const end = Math.min(text.length, index + 1000);
            return text.substring(start, end).trim();
        }
    }
    return null;
}

function calculateOverallScore(text, sections) {
    let score = 70; // Base score
    score += sections.introduction ? 5 : 0;
    score += sections.methodology ? 5 : 0;
    score += sections.results ? 5 : 0;
    score += sections.discussion ? 3 : 0;
    score += sections.conclusion ? 3 : 0;
    
    const citationScore = calculateCitationsScore(text);
    score += citationScore * 0.5;
    
    const grammarScore = calculateGrammarScore(text);
    score += grammarScore * 0.5;
    
    return Math.min(100, Math.round(score));
}

function calculateClarityScore(text) {
    const sentences = text.split(/[.!?]+/);
    const avgSentenceLength = text.split(/\s+/).length / sentences.length;
    
    let score = 80; // Base
    if (avgSentenceLength > 30) score -= 10;
    if (avgSentenceLength < 10) score -= 5;
    if (avgSentenceLength >= 15 && avgSentenceLength <= 25) score += 5;
    
    return Math.min(100, Math.max(0, score));
}

function calculateStructureScore(text, sections) {
    let score = 60; // Base
    score += sections.abstract ? 5 : 0;
    score += sections.introduction ? 5 : 0;
    score += sections.methodology ? 5 : 0;
    score += sections.results ? 5 : 0;
    score += sections.discussion ? 5 : 0;
    score += sections.conclusion ? 5 : 0;
    
    return Math.min(100, score);
}

function calculateCitationsScore(text) {
    const citationPatterns = [
        /\(\d{4}\)/g, // (2023)
        /\[\d+\]/g, // [1]
        /\b(et al\.?)\b/gi, // et al.
        /\(\w+ et al\.,? \d{4}\)/gi, // (Smith et al., 2023)
        /\b(pp?\.?\s*\d+)\b/gi // p. 123 or pp. 123-125
    ];
    
    let citationCount = 0;
    citationPatterns.forEach(pattern => {
        const matches = text.match(pattern);
        if (matches) citationCount += matches.length;
    });
    
    const words = text.split(/\s+/).length;
    const citationsPerThousandWords = (citationCount / words) * 1000;
    
    let score = 50;
    if (citationsPerThousandWords > 10) score = 95;
    else if (citationsPerThousandWords > 5) score = 85;
    else if (citationsPerThousandWords > 2) score = 70;
    else if (citationsPerThousandWords > 1) score = 60;
    
    return Math.min(100, score);
}

function calculateGrammarScore(text) {
    // Simplified grammar check - count common patterns
    let issues = 0;
    
    // Check for common errors
    const errorPatterns = [
        /\b(i|we|they) (is|am)\b/gi, // Subject-verb agreement
        /\b(their|there|they'?re)\b(?!\s+is)/gi, // Common homophone
        /\b(its|it'?s)\b(?!\s+is)/gi, // Its vs It's
        /[.!?][a-z]/g, // Missing space after punctuation
        /\s+[.,!?;:]/, // Space before punctuation
        /\b(a|an) [aeiou]/gi // Article usage
    ];
    
    errorPatterns.forEach(pattern => {
        const matches = text.match(pattern);
        if (matches) issues += matches.length;
    });
    
    const words = text.split(/\s+/).length;
    const issuesPerThousandWords = (issues / words) * 1000;
    
    let score = 95;
    if (issuesPerThousandWords > 10) score = 70;
    else if (issuesPerThousandWords > 5) score = 80;
    else if (issuesPerThousandWords > 2) score = 90;
    
    return Math.min(100, score);
}

function calculateMethodologyScore(text, methodologySection) {
    if (!methodologySection) return 60;
    
    let score = 70; // Base
    
    const methodIndicators = [
        'sample', 'participant', 'data collection', 'procedure',
        'measure', 'instrument', 'analysis', 'statistical',
        'design', 'approach', 'method', 'protocol'
    ];
    
    methodIndicators.forEach(indicator => {
        if (methodologySection.toLowerCase().includes(indicator)) {
            score += 2;
        }
    });
    
    return Math.min(100, score);
}

function calculateResultsScore(text, resultsSection) {
    if (!resultsSection) return 60;
    
    let score = 70; // Base
    
    const resultIndicators = [
        'significant', 'p value', 'correlation', 'mean',
        'standard deviation', 'percentage', 'increase', 'decrease',
        'figure', 'table', 'data show', 'results indicate'
    ];
    
    resultIndicators.forEach(indicator => {
        if (resultsSection.toLowerCase().includes(indicator)) {
            score += 2;
        }
    });
    
    return Math.min(100, score);
}

function generateSectionFeedback(sectionName, content) {
    if (!content) {
        return {
            feedback: `${sectionName.charAt(0).toUpperCase() + sectionName.slice(1)} section is missing.`,
            strengths: [],
            weaknesses: ['Section not found'],
            suggestions: [`Add a ${sectionName} section to improve structure and completeness`]
        };
    }
    
    const wordCount = content.split(/\s+/).length;
    const strengths = [];
    const weaknesses = [];
    const suggestions = [];
    
    if (wordCount > 200) {
        strengths.push('Comprehensive section with sufficient detail');
    } else if (wordCount > 100) {
        strengths.push('Adequate coverage of key points');
    } else {
        weaknesses.push('Section could be more detailed');
        suggestions.push(`Expand the ${sectionName} section with more specific information`);
    }
    
    if (content.includes('citation') || content.includes('et al') || /\(\d{4}\)/.test(content)) {
        strengths.push('Includes relevant citations');
    } else {
        weaknesses.push('Lacks proper citations');
        suggestions.push('Add citations to support key claims');
    }
    
    // Section-specific feedback
    switch(sectionName) {
        case 'abstract':
            if (wordCount < 150) {
                suggestions.push('Abstract should be more comprehensive (150-250 words recommended)');
            }
            if (!content.toLowerCase().includes('conclusion')) {
                suggestions.push('Include main conclusions in the abstract');
            }
            break;
            
        case 'introduction':
            if (!content.toLowerCase().includes('gap')) {
                suggestions.push('Clearly state the research gap your work addresses');
            }
            if (!content.toLowerCase().includes('aim') && !content.toLowerCase().includes('objective')) {
                suggestions.push('State your research aims or objectives clearly');
            }
            break;
            
        case 'methodology':
            if (!content.toLowerCase().includes('sample')) {
                weaknesses.push('Sample or participants not clearly described');
                suggestions.push('Describe your sample/participants in detail');
            }
            if (!content.toLowerCase().includes('analysis')) {
                weaknesses.push('Data analysis methods not specified');
                suggestions.push('Explain how you analyzed the data');
            }
            break;
            
        case 'results':
            if (!/\d+%|\d+\.\d+/.test(content)) {
                weaknesses.push('Lacks specific numerical results');
                suggestions.push('Include specific numbers, percentages, or statistical values');
            }
            break;
            
        case 'discussion':
            if (!content.toLowerCase().includes('limitation')) {
                suggestions.push('Acknowledge limitations of your study');
            }
            if (!content.toLowerCase().includes('implication')) {
                suggestions.push('Discuss implications of your findings');
            }
            break;
            
        case 'conclusion':
            if (!content.toLowerCase().includes('future')) {
                suggestions.push('Suggest directions for future research');
            }
            break;
    }
    
    return {
        feedback: `The ${sectionName} section ${wordCount > 150 ? 'is well-developed' : 'needs improvement'}.`,
        strengths: strengths.slice(0, 3),
        weaknesses: weaknesses.slice(0, 3),
        suggestions: suggestions.slice(0, 3)
    };
}

function extractCitations(text) {
    const citations = [];
    
    // Simple regex to find APA-style citations
    const apaPattern = /\(([A-Z][a-z]+(?:,? (?:&|and) [A-Z][a-z]+)?),? (\d{4}[a-z]?)\)/g;
    const numericPattern = /\[(\d+)\]/g;
    
    let match;
    while ((match = apaPattern.exec(text)) !== null) {
        citations.push({
            authors: match[1],
            year: match[2],
            format: 'APA',
            full: match[0]
        });
    }
    
    while ((match = numericPattern.exec(text)) !== null) {
        citations.push({
            number: match[1],
            format: 'Numeric',
            full: match[0]
        });
    }
    
    return citations.slice(0, 10);
}

function generateRelatedPapers(text) {
    const topics = extractKeywords(text, 3);
    
    const papers = [
        {
            title: `Systematic Review of ${topics[0] || 'Research'} in Academic Writing`,
            authors: 'Smith, J., Johnson, M., & Lee, K.',
            journal: 'Journal of Academic Studies',
            year: 2024,
            citations: 245,
            match: 92,
            url: 'https://doi.org/10.1234/example1'
        },
        {
            title: `Advancements in ${topics[1] || 'Methodology'} for Thesis Research`,
            authors: 'Chen, W., & Patel, R.',
            journal: 'Research Methods Review',
            year: 2023,
            citations: 178,
            match: 87,
            url: 'https://doi.org/10.1234/example2'
        },
        {
            title: `Critical Analysis of ${topics[2] || 'Findings'} in Recent Literature`,
            authors: 'Williams, T., Garcia, M., & Brown, S.',
            journal: 'Academic Research Quarterly',
            year: 2023,
            citations: 156,
            match: 84,
            url: 'https://doi.org/10.1234/example3'
        },
        {
            title: 'The Impact of Digital Tools on Thesis Writing Quality',
            authors: 'Thompson, A., & Davis, R.',
            journal: 'Educational Technology Research',
            year: 2024,
            citations: 98,
            match: 79,
            url: 'https://doi.org/10.1234/example4'
        }
    ];
    
    return papers;
}

function performPlagiarismAnalysis(text) {
    // Simplified plagiarism detection for demo
    const commonPhrases = [
        "the aim of this study", "this research investigates",
        "according to", "et al", "data were collected",
        "results indicate that", "previous studies have shown"
    ];
    
    let matches = [];
    commonPhrases.forEach(phrase => {
        if (text.toLowerCase().includes(phrase)) {
            matches.push({
                phrase: phrase,
                similarity: Math.floor(Math.random() * 30) + 10,
                source: 'Academic Corpus'
            });
        }
    });
    
    return {
        overallScore: Math.floor(Math.random() * 8) + 2, // 2-10%
        matches: matches.slice(0, 5),
        originalityScore: 100 - (Math.floor(Math.random() * 8) + 2)
    };
}

function extractKeywords(text, count) {
    const words = text.toLowerCase()
        .replace(/[^\w\s]/g, '')
        .split(/\s+/)
        .filter(word => word.length > 4);
    
    const wordFreq = {};
    words.forEach(word => {
        wordFreq[word] = (wordFreq[word] || 0) + 1;
    });
    
    return Object.entries(wordFreq)
        .sort((a, b) => b[1] - a[1])
        .slice(0, count)
        .map(entry => entry[0].charAt(0).toUpperCase() + entry[0].slice(1));
}

function generateRecommendations(scores) {
    const recommendations = [];
    
    if (scores.clarity < 75) {
        recommendations.push('Improve clarity by using simpler sentences and defining technical terms');
    }
    if (scores.structure < 75) {
        recommendations.push('Add clear section headings and improve overall organization');
    }
    if (scores.citations < 70) {
        recommendations.push('Add more recent citations (2022-2024) to strengthen literature review');
    }
    if (scores.methodology < 75) {
        recommendations.push('Provide more details about your methodology and data analysis');
    }
    if (scores.results < 75) {
        recommendations.push('Include more specific results and statistical analyses');
    }
    
    return recommendations.slice(0, 5);
}

function identifyStrengths(scores, sections) {
    const strengths = [];
    
    if (scores.clarity >= 80) strengths.push('Excellent clarity and readability');
    if (scores.structure >= 80) strengths.push('Well-organized with clear sections');
    if (scores.citations >= 80) strengths.push('Strong citation network');
    if (sections.abstract && sections.abstract.length > 150) strengths.push('Comprehensive abstract');
    if (sections.methodology && sections.methodology.length > 300) strengths.push('Detailed methodology section');
    
    return strengths.slice(0, 5);
}

function identifyWeaknesses(scores, sections) {
    const weaknesses = [];
    
    if (scores.clarity < 70) weaknesses.push('Clarity needs improvement');
    if (scores.structure < 70) weaknesses.push('Structure could be better organized');
    if (scores.citations < 60) weaknesses.push('Insufficient citations');
    if (!sections.abstract) weaknesses.push('Missing abstract section');
    if (!sections.methodology) weaknesses.push('Missing methodology section');
    if (!sections.results) weaknesses.push('Missing results section');
    if (!sections.conclusion) weaknesses.push('Missing conclusion section');
    
    return weaknesses.slice(0, 5);
}

// Get user's analysis history
app.get('/api/history', authenticateToken, (req, res) => {
    const userHistory = analysisHistory.filter(h => h.userId === req.user.id);
    res.json(userHistory);
});

// Get specific analysis by ID
app.get('/api/analysis/:id', authenticateToken, (req, res) => {
    const analysis = analysisHistory.find(h => h.id === parseInt(req.params.id));
    
    if (!analysis) {
        return res.status(404).json({ error: 'Analysis not found' });
    }
    
    if (analysis.userId !== req.user.id) {
        return res.status(403).json({ error: 'Access denied' });
    }
    
    res.json(analysis);
});

// Download analysis as PDF (simplified - returns JSON)
app.get('/api/download/:id', authenticateToken, (req, res) => {
    const analysis = analysisHistory.find(h => h.id === parseInt(req.params.id));
    
    if (!analysis) {
        return res.status(404).json({ error: 'Analysis not found' });
    }
    
    if (analysis.userId !== req.user.id) {
        return res.status(403).json({ error: 'Access denied' });
    }
    
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=analysis-${analysis.id}.json`);
    res.json(analysis);
});

// Email draft endpoint
app.post('/api/email-draft', authenticateToken, [
    body('author').notEmpty(),
    body('paper').notEmpty(),
    body('status').isIn(['unclear', 'missing', 'method'])
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { author, paper, status, customQuestion } = req.body;
    
    let question = '';
    if (status === 'unclear') {
        question = 'I found some aspects of your methodology unclear and was hoping you could provide clarification on the research design.';
    } else if (status === 'missing') {
        question = 'I noticed some data points seemed to be missing from your results section. Could you share if complete datasets are available?';
    } else {
        question = 'I had a question about your methodology, specifically regarding the data collection procedures.';
    }
    
    if (customQuestion) {
        question = customQuestion;
    }
    
    const emailContent = `Subject: Question about your paper: ${paper}

Dear Dr. ${author},

I hope this email finds you well. I recently read your fascinating paper "${paper}" and was particularly impressed by your methodology and findings.

${question}

My thesis research would greatly benefit from your insights if you could provide clarification on this aspect.

Thank you for your time and for your contribution to the field.

Best regards,
${req.user.name}
PhD Candidate`;

    res.json({
        subject: `Question about your paper: ${paper}`,
        body: emailContent,
        to: `${author.toLowerCase().replace(/\s+/g, '.')}@university.edu`
    });
});

// Save sources (breadcrumb assistant)
app.post('/api/save-source', authenticateToken, [
    body('source').notEmpty(),
    body('connection').optional(),
    body('page').optional()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { source, connection, page } = req.body;
    
    // In production, save to database
    res.json({
        message: 'Source saved successfully',
        source: {
            id: Date.now(),
            source,
            connection,
            page,
            userId: req.user.id,
            timestamp: new Date().toISOString()
        }
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File too large. Maximum size is 10MB.' });
        }
        return res.status(400).json({ error: err.message });
    }
    
    res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/api/health`);
});