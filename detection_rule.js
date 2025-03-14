

const config = {
    //  Pages we want to keep extra secure
    watchList: ['/login.jsp', '/bank/'],
  
    // Classic SQL Injection tricks used by attackers
    sqlInjectionTriggers: [
      "'--", "' OR '1'='1", "' OR 1=1--", "admin'--",
      "DROP TABLE", "SELECT * FROM", "UNION SELECT", "INSERT INTO"
    ],
  
    // Suspicious tools that attackers use for scanning
    hackerTools: ["sqlmap", "DirBuster", "Nikto", "Nmap", "Burp Suite", "ZAP"],
  
    // Security thresholds to flag unusual activity
    limits: {
      maxRequestsPerMinute: 60, // More than this = possible scanning 
      maxFailedLogins: 5,       // Too many wrong passwords? Brute-force detected!
      trackingTimeWindow: 10 * 60 * 1000 // Keep track of suspicious behavior for 10 mins
    }
  };
  
  // Storing "Who is Acting Suspicious?"
  const suspiciousIPs = {};
  
  /**
   * Spotting Suspicious Reconnaissance (Hacker Scanning)
   */
  function checkRecon(request) {
    const ip = request.clientIP;
    const userAgent = request.headers['User-Agent'] || '';
    const requestedPath = request.path;
    const now = Date.now();
  
    // If it's a new visitor, create a record for them
    if (!suspiciousIPs[ip]) {
      suspiciousIPs[ip] = { seenPaths: new Set(), userAgents: new Set(), reconScore: 0, firstSeen: now };
    }
  
    const userRecord = suspiciousIPs[ip];
  
    // Tracking paths visited and user-agent (to detect known hacker tools)
    userRecord.seenPaths.add(requestedPath);
    userRecord.userAgents.add(userAgent);
  
    // If they’re using a known hacker tool
    if (config.hackerTools.some(tool => userAgent.includes(tool))) {
      userRecord.reconScore += 50;
      alertSecurity('RECON_TOOL_DETECTED', { ip, userAgent, score: userRecord.reconScore });
    }
  
    // Are they sending too many requests? Possible scanner in action!
    if (!userRecord.requestCount) {
      userRecord.requestCount = { timestamps: [], count: 0 };
    }
  
    userRecord.requestCount.timestamps.push(now);
    userRecord.requestCount.count++;
  
    // Cleanup old requests (keep only recent ones)
    const cutoffTime = now - config.limits.trackingTimeWindow;
    userRecord.requestCount.timestamps = userRecord.requestCount.timestamps.filter(time => time >= cutoffTime);
    userRecord.requestCount.count = userRecord.requestCount.timestamps.length;
  
    if (userRecord.requestCount.count > config.limits.maxRequestsPerMinute) {
      userRecord.reconScore += 30;
      alertSecurity('HIGH_REQUEST_RATE', { ip, requestCount: userRecord.requestCount.count, score: userRecord.reconScore });
    }
  
    return false;
  }
  
  /**
   * Spotting SQL Injection Attempts
   */
  function checkSqlInjection(request) {
    const ip = request.clientIP;
    const path = request.path;
    const allParams = { ...request.queryParams, ...request.body };
  
    if (!config.watchList.some(securePath => path.includes(securePath))) return false;
  
    // Check if any parameter contains a known SQL Injection trick
    for (const [param, value] of Object.entries(allParams)) {
      if (typeof value !== 'string') continue;
  
      if (config.sqlInjectionTriggers.some(payload => value.includes(payload))) {
        alertSecurity('SQL_INJECTION_ATTEMPT', { ip, path, param, value });
        return true;
      }
    }
  
    return false;
  }
  
  /**
   * Detecting Brute-Force Login Attempts
   */
  function checkBruteForce(request, response) {
    const ip = request.clientIP;
  
    if (!request.path.includes('/login.jsp')) return false;
  
    if (response.status === 401 || response.status === 403) {
      if (!suspiciousIPs[ip]) suspiciousIPs[ip] = { failedLogins: 0 };
      suspiciousIPs[ip].failedLogins++;
  
      if (suspiciousIPs[ip].failedLogins >= config.limits.maxFailedLogins) {
        alertSecurity('BRUTE_FORCE_ATTEMPT', { ip });
      }
    }
  
    return false;
  }
  
  /**
   * Alert the Security Team (or Take Action)
   */
  function alertSecurity(alertType, details) {
    console.log(`[SECURITY ALERT] ${alertType} -`, details);
  
    // If threat is serious, take action
    if (details.score && details.score >= 80) {
      blockIP(details.ip);
    }
  }
  
  /**
   * Blocking an IP (Simulated for Now)
   */
  function blockIP(ip) {
    console.log(`[BLOCKED] IP ${ip} has been temporarily banned.`);
  }
  
  /**
   * Clean Up Old Data (Every Hour)
   */
  function cleanupOldRecords() {
    const now = Date.now();
    const cutoffTime = now - 24 * 60 * 60 * 1000; // Remove logs older than 24 hours
  
    Object.keys(suspiciousIPs).forEach(ip => {
      if (suspiciousIPs[ip].firstSeen < cutoffTime) {
        delete suspiciousIPs[ip];
      }
    });
  }
  
  setInterval(cleanupOldRecords, 60 * 60 * 1000);
  
  /**
   *  Express.js Middleware to Monitor Requests
   */
  module.exports = function securityMiddleware(req, res, next) {
    const request = {
      clientIP: req.ip,
      headers: req.headers,
      path: req.path,
      method: req.method,
      body: req.body,
      queryParams: req.query
    };
  
    const originalEnd = res.end;
    res.end = function (chunk, encoding) {
      const response = { status: res.statusCode, headers: res._headers };
  
      checkRecon(request);
      checkSqlInjection(request);
      checkBruteForce(request, response);
  
      originalEnd.call(this, chunk, encoding);
    };
  
    next();
  };
  