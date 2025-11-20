# Contributing to Cambrian ERC-8004 Agent

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Code of Conduct

Be respectful, constructive, and professional in all interactions.

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Use the bug report template
3. Include:
   - Clear description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Node version, etc.)
   - Relevant logs or screenshots

### Suggesting Features

1. Check existing feature requests
2. Explain the use case clearly
3. Describe the proposed solution
4. Consider implementation complexity

### Pull Requests

#### Before Submitting

1. **Fork the repository**
2. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**:
   - Follow existing code style
   - Add tests for new features
   - Update documentation
   - Keep commits atomic and well-described

4. **Test thoroughly**:
   ```bash
   # Run tests
   npm test

   # Test locally
   node agent/cambrian-defi-data-agent.js
   ```

5. **Update documentation**:
   - Update README if needed
   - Add/update code comments
   - Update relevant docs/ files

#### Submitting

1. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Open a pull request**:
   - Use a clear, descriptive title
   - Reference related issues
   - Describe changes and rationale
   - Include test results
   - Screenshots for UI changes

3. **Respond to feedback**:
   - Address review comments promptly
   - Push updates to the same branch
   - Request re-review when ready

## Development Setup

### Prerequisites

- Node.js 18+
- Git
- Docker (for TEE deployment)
- GCP account (for GCP deployment) or eigenx CLI (for EigenCloud)

### Local Setup

```bash
# Clone repository
git clone https://github.com/your-org/cambrian_erc8004_agent.git
cd cambrian_erc8004_agent

# Install dependencies
cd agent && npm install
cd ../mcp-server && npm install

# Configure environment
cp .env.example .env
# Edit .env with your credentials

# Run agent
cd agent
node cambrian-defi-data-agent.js

# Run MCP server (in another terminal)
cd mcp-server
npm start
```

## Code Style

### JavaScript/TypeScript

- Use ES6+ features
- 2-space indentation
- Semicolons required
- Descriptive variable names
- JSDoc comments for functions

Example:
```javascript
/**
 * Generate EIP-712 signature for feedback authorization
 * @param {string} clientAddress - Client wallet address
 * @param {number} indexLimit - Maximum feedback index
 * @param {number} expiry - Signature expiration timestamp
 * @returns {Promise<Object>} Signed feedback authorization
 */
async function generateFeedbackAuth(clientAddress, indexLimit, expiry) {
  // Implementation
}
```

### Go

- Follow standard Go formatting (`gofmt`)
- Meaningful package names
- Error handling required
- Comments for exported functions

### Python

- PEP 8 style guide
- Type hints where applicable
- Docstrings for functions/classes

## Testing Guidelines

### Unit Tests

- Test individual functions
- Mock external dependencies
- Aim for >80% code coverage

### Integration Tests

- Test component interactions
- Test against real MCP server
- Verify ERC-8004 compliance

### TEE Tests

- Test attestation verification
- Test TLS certificate pinning
- Test complete dual-TEE flow

## Security

### Reporting Vulnerabilities

See [SECURITY.md](SECURITY.md) for vulnerability reporting procedures.

### Security Practices

- Never commit secrets or private keys
- Use environment variables for sensitive data
- Validate all external inputs
- Implement rate limiting
- Review security implications of changes

## Documentation

### Code Documentation

- Document all public functions
- Explain complex algorithms
- Add inline comments for clarity
- Keep comments up-to-date

### README Updates

Update README.md when:
- Adding new features
- Changing API endpoints
- Updating dependencies
- Modifying deployment process

### docs/ Updates

Update docs/ when:
- Changing architecture
- Adding deployment options
- Updating configuration
- Changing security model

## Commit Messages

Format:
```
type(scope): brief description

Detailed explanation if needed

Fixes #123
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Formatting, no code change
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance tasks

Examples:
```
feat(agent): add support for OHLCV data endpoint

Implements historical OHLCV data fetching with caching
and rate limiting.

Closes #45

fix(mcp-server): handle connection timeouts gracefully

Added retry logic and better error messages for
connection failures.

docs(deployment): add EigenCloud deployment guide

Comprehensive guide for deploying to EigenCloud TEE
platform.
```

## Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation
- `refactor/description` - Code refactoring
- `test/description` - Test additions

## Release Process

1. Update version in package.json
2. Update CHANGELOG.md
3. Create release branch: `release/vX.Y.Z`
4. Run full test suite
5. Create GitHub release with notes
6. Tag with version: `vX.Y.Z`

## Questions?

- Open a GitHub Discussion
- Ask in pull request comments
- Email: support@cambrian.network

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing!** Every contribution, no matter how small, makes this project better.
