container-ids-platform/
├── README.md
├── .gitignore
├── docker-compose.yml              # Local development orchestration
├── Makefile                        # Build automation
│
├── packages/
│   ├── agent/                      # Go agent embedded in base image
│   │   ├── cmd/
│   │   │   └── agent/
│   │   │       └── main.go         # Agent entry point
│   │   ├── internal/
│   │   │   ├── collector/          # Data collection (eBPF, syscalls)
│   │   │   │   ├── ebpf/
│   │   │   │   │   ├── loader.go
│   │   │   │   │   └── probes.bpf.c
│   │   │   │   ├── syscall.go
│   │   │   │   ├── network.go
│   │   │   │   ├── filesystem.go
│   │   │   │   └── process.go
│   │   │   ├── connection/         # Connection service
│   │   │   │   ├── server.go       # HTTP/gRPC server for remote access
│   │   │   │   ├── auth.go
│   │   │   │   └── handler.go
│   │   │   ├── publisher/          # RabbitMQ publisher
│   │   │   │   ├── rabbitmq.go
│   │   │   │   └── serializer.go
│   │   │   ├── config/
│   │   │   │   └── config.go
│   │   │   └── models/
│   │   │       └── events.go       # Event structs
│   │   ├── go.mod
│   │   ├── go.sum
│   │   ├── Dockerfile              # Agent binary builder
│   │   └── README.md
│   │
│   ├── base-image/                 # Custom Docker base image
│   │   ├── Dockerfile              # Ubuntu + agent + tools
│   │   ├── entrypoint.sh           # Startup script
│   │   ├── config/
│   │   │   └── agent.yaml          # Default agent config
│   │   └── README.md               # Usage instructions for enterprises
│   │
│   ├── backend/                    # FastAPI platform backend
│   │   ├── app/
│   │   │   ├── __init__.py
│   │   │   ├── main.py             # FastAPI app entry
│   │   │   ├── api/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── v1/
│   │   │   │   │   ├── __init__.py
│   │   │   │   │   ├── auth.py     # Login, registration
│   │   │   │   │   ├── hosts.py    # Host management
│   │   │   │   │   ├── containers.py
│   │   │   │   │   ├── alerts.py
│   │   │   │   │   └── telemetry.py
│   │   │   │   └── deps.py         # Dependencies (DB, auth)
│   │   │   ├── core/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── config.py       # Settings
│   │   │   │   ├── security.py     # JWT, password hashing
│   │   │   │   └── database.py     # PostgreSQL connection
│   │   │   ├── models/             # SQLAlchemy models
│   │   │   │   ├── __init__.py
│   │   │   │   ├── user.py
│   │   │   │   ├── api_key.py
│   │   │   │   ├── docker_host.py
│   │   │   │   ├── container.py
│   │   │   │   ├── telemetry.py
│   │   │   │   ├── alert.py
│   │   │   │   └── behavioral_profile.py
│   │   │   ├── schemas/            # Pydantic schemas
│   │   │   │   ├── __init__.py
│   │   │   │   ├── user.py
│   │   │   │   ├── host.py
│   │   │   │   ├── container.py
│   │   │   │   └── alert.py
│   │   │   ├── services/           # Business logic
│   │   │   │   ├── __init__.py
│   │   │   │   ├── rabbitmq.py     # Consumer setup
│   │   │   │   ├── telemetry.py    # Telemetry processing
│   │   │   │   └── alert.py        # Alert management
│   │   │   └── ml/                 # ML integration (placeholder for now)
│   │   │       ├── __init__.py
│   │   │       └── client.py       # ML engine API client
│   │   ├── alembic/                # Database migrations
│   │   │   ├── env.py
│   │   │   ├── versions/
│   │   │   └── alembic.ini
│   │   ├── tests/
│   │   │   ├── __init__.py
│   │   │   ├── test_auth.py
│   │   │   └── test_hosts.py
│   │   ├── requirements.txt
│   │   ├── Dockerfile
│   │   └── README.md
│   │
│   ├── ml-engine/                  # ML detection service (future)
│   │   ├── app/
│   │   │   ├── __init__.py
│   │   │   ├── main.py
│   │   │   ├── consumer.py         # RabbitMQ consumer
│   │   │   ├── models/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── isolation_forest.py
│   │   │   │   └── random_forest.py
│   │   │   ├── features/
│   │   │   │   ├── __init__.py
│   │   │   │   └── extractor.py
│   │   │   └── baseline/
│   │   │       ├── __init__.py
│   │   │       └── profiler.py
│   │   ├── requirements.txt
│   │   ├── Dockerfile
│   │   └── README.md
│   │
│   └── portal/                     # Next.js web dashboard
│       ├── src/
│       │   ├── app/
│       │   │   ├── layout.tsx
│       │   │   ├── page.tsx        # Landing/login
│       │   │   ├── dashboard/
│       │   │   │   ├── page.tsx    # Host overview
│       │   │   │   └── [hostId]/
│       │   │   │       └── page.tsx # Per-container detail
│       │   │   └── api/            # Next.js API routes (optional)
│       │   │       └── auth/
│       │   │           └── [...nextauth].ts
│       │   ├── components/
│       │   │   ├── ui/             # Reusable UI components
│       │   │   ├── HostCard.tsx
│       │   │   ├── ContainerPanel.tsx
│       │   │   ├── AlertList.tsx
│       │   │   └── charts/
│       │   │       ├── SystemCallChart.tsx
│       │   │       └── NetworkChart.tsx
│       │   ├── lib/
│       │   │   ├── api.ts          # Backend API client
│       │   │   └── auth.ts         # Auth utilities
│       │   └── types/
│       │       ├── index.ts
│       │       └── api.ts
│       ├── public/
│       ├── package.json
│       ├── tsconfig.json
│       ├── next.config.js
│       ├── tailwind.config.js
│       ├── Dockerfile
│       └── README.md
│
├── scripts/                        # Utility scripts
│   ├── build-base-image.sh
│   ├── setup-dev.sh
│   └── deploy.sh
│
├── infra/                          # Infrastructure as code (optional)
│   ├── docker/
│   │   └── docker-compose.prod.yml
│   └── k8s/                        # Future Kubernetes manifests
│
└── docs/                           # Documentation
    ├── architecture.md
    ├── api.md
    ├── deployment.md
    └── enterprise-guide.md         # How enterprises use the base image
