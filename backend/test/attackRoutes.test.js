const request = require('supertest');
const mongoose = require('mongoose'); // Import mongoose to manage database connection
const app = require('../server'); // Adjust the path as necessary to import your Express app
require('dotenv').config({ path: './.env.test' });

// Setting up database connection before running tests
beforeAll(async () => {
    // Ensure you connect to a test database; the URI should be configured in your environment variables specifically for testing
    await mongoose.connect(process.env.TEST_DB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true
    });
});

// Main describe block for Attack Routes
describe('Attack Routes', () => {
    // Test for fetching top countries by attack count
    describe('GET /api/attacks/top-countries', () => {
        it('should fetch the top countries by attack count', async () => {
            const response = await request(app).get('/api/attacks/top-countries');
            expect(response.statusCode).toBe(200);
            expect(response.body).toBeInstanceOf(Array);
            expect(response.body.length).toBeGreaterThan(0);
            response.body.forEach((item) => {
                expect(item).toHaveProperty('_id');
                expect(item).toHaveProperty('count');
                expect(typeof item._id).toBe('string');
                expect(typeof item.count).toBe('number');
            });
        });

        // Optional: Add a test for handling errors when the endpoint fails
        it('should handle errors when fetching top countries', async () => {
            // Simulate an error scenario if possible or mock it
            const response = await request(app).get('/api/attacks/top-countries');
            expect(response.statusCode).not.toBe(500); // Assuming your server responds with status 500 on error
        });
    });

    // Test for fetching top attack types
    describe('GET /api/attacks/top-attack-types', () => {
        it('should fetch the top attack types', async () => {
            const response = await request(app).get('/api/attacks/top-attack-types');
            expect(response.statusCode).toBe(200);
            expect(response.body).toBeInstanceOf(Array);
            expect(response.body.length).toBeGreaterThan(0);
            response.body.forEach((item) => {
                expect(item).toHaveProperty('_id');
                expect(item).toHaveProperty('count');
            });
        });
    });

    // Test for fetching top source IPs
    describe('GET /api/attacks/top-ips', () => {
        it('should fetch the top source IPs', async () => {
            const response = await request(app).get('/api/attacks/top-ips');
            expect(response.statusCode).toBe(200);
            expect(response.body).toBeInstanceOf(Array);
            expect(response.body.length).toBeGreaterThan(0);
            response.body.forEach((item) => {
                expect(item).toHaveProperty('_id');
                expect(item).toHaveProperty('count');
            });
        });
    });

    // ✅ Test: Fetch Attack Trends Over Time
    describe('GET /api/attacks/attack-trends', () => {
        it('should fetch attack trends over time', async () => {
            const response = await request(app).get('/api/attacks/attack-trends');
            expect(response.statusCode).toBe(200);
            expect(response.body).toBeInstanceOf(Array);
            response.body.forEach((item) => {
                expect(item).toHaveProperty('_id');
                expect(item).toHaveProperty('count');
            });
        });
    });

    // ✅ Test: Fetch Protocol Breakdown
    describe('GET /api/attacks/protocol-breakdown', () => {
        it('should fetch a breakdown of attack protocols', async () => {
            const response = await request(app).get('/api/attacks/protocol-breakdown');
            expect(response.statusCode).toBe(200);
            expect(response.body).toBeInstanceOf(Array);
            response.body.forEach((item) => {
                expect(item).toHaveProperty('_id');
                expect(item).toHaveProperty('count');
            });
        });
    });

    // ✅ Test: Fetch Severity Distribution
    describe('GET /api/attacks/severity-distribution', () => {
        it('should fetch severity distribution of attacks', async () => {
            const response = await request(app).get('/api/attacks/severity-distribution');
            expect(response.statusCode).toBe(200);
            expect(response.body).toBeInstanceOf(Array);
            response.body.forEach((item) => {
                expect(item).toHaveProperty('_id');
                expect(item).toHaveProperty('count');
            });
        });
    });

    // ✅ Test: Fetch Port Scanning Analysis
    describe('GET /api/attacks/port-scanning', () => {
        it('should fetch port scanning analysis data', async () => {
            const response = await request(app).get('/api/attacks/port-scanning');
            expect(response.statusCode).toBe(200);
            expect(response.body).toBeInstanceOf(Array);
            response.body.forEach((item) => {
                expect(item).toHaveProperty('_id');
                expect(item).toHaveProperty('count');
            });
        });
    });

    // ✅ Test: Fetch Source ASN Analysis
    describe('GET /api/attacks/source-asn', () => {
        it('should fetch analysis of attack sources by ASN', async () => {
            const response = await request(app).get('/api/attacks/source-asn');
            expect(response.statusCode).toBe(200);
            expect(response.body).toBeInstanceOf(Array);
            response.body.forEach((item) => {
                expect(item).toHaveProperty('_id');
                expect(item).toHaveProperty('count');
            });
        });
    });

    // ✅ Test: Fetch Comparative Traffic Analysis
    describe('GET /api/attacks/comparative-traffic', () => {
        it('should fetch comparative attack traffic analysis', async () => {
            const response = await request(app).get('/api/attacks/comparative-traffic');
            expect(response.statusCode).toBe(200);
            expect(response.body).toBeInstanceOf(Array);
            response.body.forEach((item) => {
                expect(item).toHaveProperty('_id');
                expect(item).toHaveProperty('count');
            });
        });
    });

    // ✅ Test: Fetch Global Threats
    describe("GET /api/attacks/global-threats", () => {
        it("should fetch live global threat intelligence data", async () => {
            const response = await request(app).get("/api/attacks/global-threats");
            expect(response.statusCode).toBe(200);
            expect(response.body).toBeInstanceOf(Array);
            expect(response.body.length).toBeGreaterThan(0);
            response.body.forEach((item) => {
                expect(item).toHaveProperty("timestamp");
                expect(item).toHaveProperty("sourceIP");  // Matches API response
                expect(item).toHaveProperty("targetPort"); // Matches API response

            });
        });
    });
    

});

// Clean up after all tests are done, by closing the database connection
afterAll(async () => {
    await mongoose.connection.close();
});
