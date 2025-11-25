const axios = require('axios');

const total = new Map();
const activeTimers = new Map();
const statistics = {
    totalShares: 0,
    activeSessions: 0,
    successfulShares: 0,
    failedShares: 0
};

const STOP_ACCESS_KEY = "share";

exports.handler = async (event, context) => {
    const path = event.path;
    const method = event.httpMethod;

    // Set CORS headers
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
    };

    // Handle preflight
    if (method === 'OPTIONS') {
        return {
            statusCode: 200,
            headers,
            body: ''
        };
    }

    try {
        if (path.includes('/api/submit') && method === 'POST') {
            const { cookie, url, amount, interval } = JSON.parse(event.body);
            
            if (!cookie || !url || !amount || !interval) {
                return {
                    statusCode: 400,
                    headers,
                    body: JSON.stringify({ error: 'Missing state, url, amount, or interval' })
                };
            }

            const cookies = await convertCookie(cookie);
            if (!cookies) {
                return {
                    statusCode: 400,
                    headers,
                    body: JSON.stringify({ status: 500, error: 'Invalid cookies' })
                };
            }

            await share(cookies, url, amount, interval);
            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({ status: 200 })
            };
        }

        if ((path.includes('/total') || path === '/.netlify/functions/submit') && method === 'GET') {
            const data = Array.from(total.values()).map((link, index) => ({
                session: index + 1,
                url: link.url,
                count: link.count,
                id: link.id,
                target: link.target,
                postId: link.postId,
                fbLink: `https://facebook.com/${link.id}`
            }));
            return {
                statusCode: 200,
                headers,
                body: JSON.stringify(data || [])
            };
        }

        if (path.includes('/statistics') && method === 'GET') {
            statistics.activeSessions = total.size;
            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({
                    totalShares: statistics.totalShares,
                    activeSessions: statistics.activeSessions,
                    successRate: statistics.totalShares > 0 ? 
                        ((statistics.successfulShares / statistics.totalShares) * 100).toFixed(1) : 0
                })
            };
        }

        if (path.includes('/api/stop') && method === 'POST') {
            const { sessionId, accessKey } = JSON.parse(event.body);
            
            if (accessKey !== STOP_ACCESS_KEY) {
                return {
                    statusCode: 403,
                    headers,
                    body: JSON.stringify({ status: 403, error: 'Invalid access key' })
                };
            }

            let sessionToStop = null;
            for (const [postId, session] of total.entries()) {
                if (session.id === sessionId) {
                    sessionToStop = { postId, session };
                    break;
                }
            }

            if (!sessionToStop) {
                return {
                    statusCode: 404,
                    headers,
                    body: JSON.stringify({ status: 404, error: 'Session not found' })
                };
            }

            const timer = activeTimers.get(sessionToStop.postId);
            if (timer) {
                clearInterval(timer.interval);
                clearTimeout(timer.timeout);
                activeTimers.delete(sessionToStop.postId);
            }

            total.delete(sessionToStop.postId);
            statistics.activeSessions = total.size;

            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({ status: 200, message: 'Session stopped successfully' })
            };
        }

        return {
            statusCode: 404,
            headers,
            body: JSON.stringify({ error: 'Not found' })
        };

    } catch (err) {
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: err.message })
        };
    }
};

async function share(cookies, url, amount, interval) {
    const id = await getPostID(url);
    const accessToken = await getAccessToken(cookies);
    if (!id) {
        throw new Error("Unable to get link id: invalid URL, it's either a private post or visible to friends only");
    }
    const postId = total.has(id) ? id + Date.now() : id;

    total.set(postId, {
        url,
        id,
        count: 0,
        target: amount,
        postId: postId
    });

    statistics.activeSessions = total.size;

    const headers = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate',
        'connection': 'keep-alive',
        'content-length': '0',
        'cookie': cookies,
        'host': 'graph.facebook.com'
    };

    let sharedCount = 0;
    let intervalTimer;
    let timeoutTimer;

    // Faster sharing - reduced delay between shares
    const optimizedInterval = Math.max(1000, interval * 500); // Faster interval

    async function sharePost() {
        try {
            const response = await axios.post(`https://graph.facebook.com/me/feed?link=https://m.facebook.com/${id}&published=0&access_token=${accessToken}`, {}, {
                headers
            });
            if (response.status !== 200) {
                statistics.failedShares++;
            } else {
                total.set(postId, {
                    ...total.get(postId),
                    count: total.get(postId).count + 1,
                });
                sharedCount++;
                statistics.totalShares++;
                statistics.successfulShares++;
            }
            if (sharedCount >= parseInt(amount)) {
                clearInterval(intervalTimer);
                clearTimeout(timeoutTimer);
                activeTimers.delete(postId);
                total.delete(postId);
                statistics.activeSessions = total.size;
            }
        } catch (error) {
            statistics.failedShares++;
            if (sharedCount >= parseInt(amount)) {
                clearInterval(intervalTimer);
                clearTimeout(timeoutTimer);
                activeTimers.delete(postId);
                total.delete(postId);
                statistics.activeSessions = total.size;
            }
        }
    }

    // Start sharing immediately and then at intervals
    sharePost(); // Immediate first share
    intervalTimer = setInterval(sharePost, optimizedInterval);
    
    timeoutTimer = setTimeout(() => {
        clearInterval(intervalTimer);
        activeTimers.delete(postId);
        total.delete(postId);
        statistics.activeSessions = total.size;
    }, amount * optimizedInterval);

    activeTimers.set(postId, {
        interval: intervalTimer,
        timeout: timeoutTimer
    });
}

async function getPostID(url) {
    try {
        const response = await axios.post('https://id.traodoisub.com/api.php', `link=${encodeURIComponent(url)}`, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
        });
        return response.data.id;
    } catch (error) {
        return null;
    }
}

async function getAccessToken(cookie) {
    try {
        const headers = {
            'authority': 'business.facebook.com',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'accept-language': 'vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
            'cache-control': 'max-age=0',
            'cookie': cookie,
            'referer': 'https://www.facebook.com/',
            'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Linux"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
        };
        const response = await axios.get('https://business.facebook.com/content_management', {
            headers
        });
        const token = response.data.match(/"accessToken":\s*"([^"]+)"/);
        if (token && token[1]) {
            return token[1];
        }
    } catch (error) {
        return null;
    }
}

async function convertCookie(cookie) {
    return new Promise((resolve, reject) => {
        try {
            const cookies = JSON.parse(cookie);
            const sbCookie = cookies.find(cookies => cookies.key === "sb");
            if (!sbCookie) {
                reject("Detect invalid appstate please provide a valid appstate");
            }
            const sbValue = sbCookie.value;
            const data = `sb=${sbValue}; ${cookies.slice(1).map(cookies => `${cookies.key}=${cookies.value}`).join('; ')}`;
            resolve(data);
        } catch (error) {
            reject("Error processing appstate please provide a valid appstate");
        }
    });
}