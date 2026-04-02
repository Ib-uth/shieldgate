# ShieldGate API Gateway

A production-ready API gateway with JWT authentication, rate limiting, structured logging, and ML-based threat detection built with FastAPI.

## 🚀 Features

- **JWT Authentication**: RS256 asymmetric key authentication with role-based access control
- **Rate Limiting**: Redis-based sliding window rate limiting (IP and user-based)
- **Request Proxying**: Async proxying to downstream services with header management
- **Structured Logging**: JSON logging with PostgreSQL storage and real-time monitoring
- **ML Threat Detection**: Isolation Forest model for anomaly detection and threat scoring
- **Admin Dashboard**: React-based real-time monitoring interface
- **Health Monitoring**: Comprehensive health checks for all services
- **Production Ready**: Docker containerization with multi-stage builds

## Getting Started

1. **Set CORS on Render**: Configure **`ALLOWED_ORIGINS`** on the **gateway** web service to the **admin UI** origin (the URL where the React app is hosted), not the gateway URL. Example: `https://shieldgate.onrender.com`. Use a comma-separated list if you have several origins (e.g. local dev + production).

2. **Admin UI build-time API URL**: Set **`VITE_API_URL`** in the **Render Static Site** (or your build environment) to the **gateway** base URL, e.g. `https://shieldgate-gateway.onrender.com` (no trailing slash). Vite inlines this at **build time**; it is not a runtime env var in the browser bundle. If you omit it, the bundled admin UI may call `http://localhost:8000` and fail in production.

3. **Sample JWTs (development only)**: Set **`ENVIRONMENT=development`** on the gateway, then visit **`GET /auth/test-tokens`** on the gateway base URL (e.g. `https://shieldgate-gateway.onrender.com/auth/test-tokens`) to retrieve sample **admin**, **user**, and **readonly** JWTs. With **`ENVIRONMENT=production`**, this endpoint returns **404**.

4. **Log in to the dashboard**: Build the admin UI with **`VITE_API_URL`** pointing at the gateway. Open the admin site and sign in with your credentials. You can also use a JWT from step 3 when testing API clients directly.

**Example deployed URLs**:

- Gateway API: `https://shieldgate-gateway.onrender.com`
- Admin dashboard: `https://shieldgate.onrender.com`

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Admin UI      │    │   API Gateway   │    │  Downstream     │
│   (React)       │◄──►│   (FastAPI)     │◄──►│   Services      │
│   Port: 3000    │    │   Port: 8000    │    │   Port: 8001    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │  PostgreSQL     │
                       │   Port: 5432    │
                       └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │     Redis       │
                       │   Port: 6379    │
                       └─────────────────┘
```

## 🛠️ Tech Stack

### Backend
- **FastAPI**: Python web framework
- **PostgreSQL**: Primary database
- **Redis**: Rate limiting and caching
- **SQLAlchemy**: ORM and database management
- **httpx**: Async HTTP client for proxying
- **structlog**: Structured JSON logging
- **scikit-learn**: ML threat detection
- **python-jose**: JWT handling

### Frontend
- **React 18**: Admin dashboard
- **TypeScript**: Type safety
- **Tailwind CSS**: Styling
- **Recharts**: Data visualization
- **React Query**: Data fetching and caching
- **Vite**: Build tool

### DevOps
- **Docker**: Containerization
- **Docker Compose**: Local development
- **Multi-stage builds**: Optimized images

## 🏗️ Architecture Decisions

### 1. JWT Signing Algorithm: RS256 vs HS256
**Problem**: Choose between symmetric (HS256) and asymmetric (RS256) JWT signing.
**Options**: HS256 is simpler with single secret key, RS256 is more secure with public/private key pair.
**Decision**: RS256 asymmetric encryption.
**Tradeoff**: RS256 requires key management but provides better security separation and allows public key distribution without exposing private keys.

### 2. Rate Limiting: Custom Redis vs Third-party Libraries
**Problem**: Implement rate limiting with existing libraries or custom Redis implementation.
**Options**: Use FastAPI extensions like slowapi-rate-limit or build custom sliding window with Redis.
**Decision**: Custom Redis sliding window implementation.
**Tradeoff**: Custom implementation is more complex but provides precise control over sliding window behavior and better integration with existing Redis infrastructure.

### 3. Threat Detection: Isolation Forest vs Supervised Classifier
**Problem**: Choose ML approach for anomaly detection in request patterns.
**Options**: Supervised classifier with labeled data or unsupervised Isolation Forest.
**Decision**: Isolation Forest unsupervised learning.
**Tradeoff**: Isolation Forest doesn't require labeled training data and can detect novel attack patterns, though it may have more false positives than supervised approaches.

### 4. Request Logging: PostgreSQL vs Dedicated Log Store
**Problem**: Store structured logs in specialized logging system vs primary database.
**Options**: Use Loki/Elasticsearch for log aggregation or PostgreSQL for integrated storage.
**Decision**: PostgreSQL for request logging.
**Tradeoff**: PostgreSQL provides ACID compliance and simplifies infrastructure at the cost of specialized log querying capabilities, which is acceptable for this use case.

### 5. Repository Structure: Monorepo vs Separate Repos
**Problem**: Organize codebase with admin UI in same repository or separate repos.
**Options**: Single monorepo with all components or separate repositories for backend and frontend.
**Decision**: Monorepo with admin UI included.
**Tradeoff**: Monorepo simplifies development and deployment coordination but couples backend/frontend release cycles, which is acceptable for a portfolio project.

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Git

### 1. Clone and Setup
```bash
git clone <repository-url>
cd shieldgate
```

### 2. Start Services
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### 3. Access Services
- **Admin Dashboard**: http://localhost:3000
- **API Gateway**: http://localhost:8000
- **Mock Service**: http://localhost:8001
- **Health Check**: http://localhost:8000/health

## 📋 API Endpoints

### Gateway Routes
- `GET /` - Root endpoint
- `GET /health` - Health check
- `GET /metrics` - Request metrics
- `GET /admin/stats` - Admin statistics (admin only)
- `GET /admin/blocked-ips` - Blocked IPs list (admin only)
- `POST /admin/block-ip` - Block IP (admin only)
- `POST /admin/unblock-ip/{ip}` - Unblock IP (admin only)
- `/*` - Proxy to downstream service

### Mock Service Routes
- `GET /public` - Public endpoint (no auth)
- `GET /user` - User endpoint (requires user role)
- `GET /admin` - Admin endpoint (requires admin role)

## 🔐 Authentication

### JWT Tokens
The system uses RS256 asymmetric encryption for JWT tokens.

#### Generate Keys (Development)
```bash
python scripts/generate_keys.py
```

#### Sample Tokens
```bash
# Generate sample tokens for testing
python scripts/generate_keys.py
```

#### Usage
```bash
# Public endpoint (no auth required)
curl http://localhost:8000/public

# User endpoint (requires user role)
curl -H "Authorization: Bearer <user-token>" http://localhost:8000/user

# Admin endpoint (requires admin role)
curl -H "Authorization: Bearer <admin-token>" http://localhost:8000/admin
```

### Role Hierarchy
1. **admin**: Full access to all endpoints
2. **user**: Access to user and public endpoints
3. **readonly**: Read-only access to public endpoints

## 🛡️ Security Features

### Rate Limiting
- **IP-based**: 60 requests/minute for unauthenticated requests
- **User-based**: 300 requests/minute for authenticated users
- **Sliding window**: Custom Redis implementation
- **Headers**: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After`

### Threat Detection
- **ML Model**: Isolation Forest for anomaly detection
- **Features**: IP request frequency, user agent entropy, request patterns
- **Scoring**: 0.0 (minimal) to 1.0 (critical)
- **Actions**: Flag (>0.7), Block (>0.9)
- **Headers**: `X-Threat-Score`, `X-Threat-Action`

### Request Logging
- **Structured**: JSON format with consistent schema
- **Storage**: PostgreSQL with optimized indexes
- **Fields**: request_id, timestamp, method, path, status, latency, user_id, ip, threat_score
- **Real-time**: Available in admin dashboard

## 📊 Monitoring

### Health Checks
```bash
# Comprehensive health check
curl http://localhost:8000/health

# Response example
{
  "status": "healthy",
  "timestamp": "2024-01-01T10:00:00Z",
  "version": "1.0.0",
  "services": {
    "redis": {"status": "healthy", "response_time_ms": 1.2},
    "database": {"status": "healthy", "response_time_ms": 5.4},
    "downstream": {"status": "healthy", "response_time_ms": 12.1}
  }
}
```

### Metrics
```bash
# Request metrics (last hour)
curl http://localhost:8000/metrics?hours=1

# Response example
{
  "timestamp": "2024-01-01T10:00:00Z",
  "period_hours": 1,
  "total_requests": 1250,
  "error_rate": 2.4,
  "top_blocked_ips": [
    {"ip": "192.168.1.100", "blocked_count": 15}
  ],
  "threat_score_distribution": {
    "minimal": 1100,
    "low": 100,
    "medium": 30,
    "high": 15,
    "critical": 5
  }
}
```

## 🧪 Testing

### Unit Tests
```bash
# Run all tests
pytest apps/gateway/tests/

# Run with coverage
pytest --cov=apps/gateway --cov-report=html

# Run specific test file
pytest apps/gateway/tests/test_auth.py
```

### Integration Tests
```bash
# Test rate limiting
python -m pytest tests/test_ratelimit.py -v

# Test threat detection
python -m pytest tests/test_threat_detection.py -v
```

### Load Testing
```bash
# Install load testing tool
pip install locust

# Run load test
locust -f tests/locustfile.py --host=http://localhost:8000
```

## 🔧 Configuration

### Environment Variables
```bash
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/shieldgate

# Services
DOWNSTREAM_URL=http://localhost:8001
REDIS_URL=redis://localhost:6379

# JWT
JWT_PRIVATE_KEY_PATH=./keys/private.pem
JWT_PUBLIC_KEY_PATH=./keys/public.pem

# Rate Limiting
RATE_LIMIT_IP_REQUESTS=60
RATE_LIMIT_IP_WINDOW=60
RATE_LIMIT_USER_REQUESTS=300
RATE_LIMIT_USER_WINDOW=60

# Threat Detection
THREAT_SCORE_FLAG_THRESHOLD=0.7
THREAT_SCORE_BLOCK_THRESHOLD=0.9
THREAT_MODEL_PATH=./models/threat_model.joblib
```

### Docker Environment
All environment variables are pre-configured in `docker-compose.yml`.

## 🚀 Deployment

### Local Development
```bash
# Start development environment
docker-compose up -d

# View logs
docker-compose logs -f gateway
```

### Production Considerations
- Use environment-specific configuration
- Enable HTTPS/TLS
- Use managed Redis and PostgreSQL
- Configure proper logging and monitoring
- Set up backup and disaster recovery
- Implement proper secret management

### Render Deployment

ShieldGate can be deployed to Render using the provided `render.yaml` configuration file.

#### Prerequisites
- Render account
- GitHub repository with the code
- Neon PostgreSQL database (external)
- Redis instance (Render managed)

#### Quick Deploy
1. **Connect Repository**: Link your GitHub repository to Render
2. **Create Services**: Render will automatically create services from `render.yaml`
3. **Configure Secrets**: Set the `DATABASE_URL` secret in the gateway service
4. **Deploy**: Render will build and deploy the services

#### Services Configuration
- **Gateway Web Service**: Docker-based, port 8000, auto-scaling
- **Redis Instance**: Managed Redis for rate limiting and caching
- **Neon PostgreSQL**: External PostgreSQL database for request logging

#### Environment Variables
The `render.yaml` file configures all required environment variables:
- `DATABASE_URL`: Pre-configured with Neon PostgreSQL connection string
- `REDIS_URL`: Automatically set from Redis service connection
- All other variables use sensible defaults

#### Manual Setup
If not using `render.yaml`, create these services manually:

1. **Neon PostgreSQL Database**
   - Use your existing Neon database
   - Set connection string as `DATABASE_URL` environment variable
   - Ensure SSL mode is enabled

2. **Redis Instance**
   - Type: Redis
   - Connection string automatically available to gateway

3. **Web Service**
   - Type: Docker
   - Dockerfile path: `Dockerfile.gateway`
   - Port: 8000
   - Add environment variables from `.env.example`

#### Health Checks
Render automatically monitors the `/health` endpoint for service health.

## 📈 Performance

### Benchmarks
- **Latency**: <10ms additional overhead
- **Throughput**: 1000+ requests/second
- **Memory**: <200MB per container
- **Storage**: Optimized indexes for fast queries

### Scaling
- **Horizontal**: Multiple gateway instances behind load balancer
- **Database**: Read replicas for metrics queries
- **Redis**: Cluster for high availability

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

- **Issues**: Create an issue on GitHub
- **Documentation**: Check the `/docs` directory
- **Examples**: See the `/examples` directory

---

## 🔍 Threat Model

### Attack Vectors Mitigated
1. **Brute Force**: Rate limiting and IP blocking
2. **DDoS**: Request throttling and threat detection
3. **Injection**: Input validation and parameterized queries
4. **Authentication Bypass**: Strong JWT validation
5. **Privilege Escalation**: Role-based access control
6. **Data Exfiltration**: Request logging and monitoring

### Security Headers
- `X-Request-ID`: Request tracking
- `X-Threat-Score`: Threat level indication
- `X-RateLimit-*`: Rate limiting information
- `X-Forwarded-*`: Proxy information

### Monitoring and Alerting
- Real-time threat detection
- Automated IP blocking
- Comprehensive audit logging
- Performance metrics tracking

---

Built with ❤️ for production-ready API gateway security.
