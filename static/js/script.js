function runFullScan() {
    const url = document.getElementById('fullScanUrl').value.trim();
    if (!url) {
        alert('Please enter a valid URL');
        return;
    }

    document.getElementById('loading').style.display = 'block';
    document.getElementById('scanResults').innerHTML = '';

    fetch('/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('loading').style.display = 'none';
        const resultsDiv = document.getElementById('scanResults');
        resultsDiv.innerHTML = '<h5 class="mt-3">Scan Results:</h5>';
        
        data.results.forEach(result => {
            const isVulnerable = result.includes('Vulnerable');
            const resultDiv = document.createElement('div');
            resultDiv.className = `result-item ${isVulnerable ? 'vulnerable' : 'safe'}`;
            resultDiv.textContent = result;
            resultsDiv.appendChild(resultDiv);
        });
    })
    .catch(error => {
        document.getElementById('loading').style.display = 'none';
        console.error('Error:', error);
        alert('Scan failed: ' + error.message);
    });
}

function runSingleScan(category, inputId, resultDivId) {
    console.log('runSingleScan called with:', category, inputId, resultDivId);
    const url = document.getElementById(inputId).value.trim();
    if (!url) {
        alert('Please enter a valid URL');
        return;
    }

    const resultDiv = document.getElementById(resultDivId);
    if (!resultDiv) {
        alert('Result container not found: ' + resultDivId);
        return;
    }

    // Show loading spinner
    resultDiv.innerHTML = '<div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div>';

    fetch('/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url, category: category })
    })
    .then(response => response.json())
    .then(data => {
        resultDiv.innerHTML = '';
        if (!data.results || data.results.length === 0) {
            resultDiv.innerHTML = '<div class="alert alert-warning">No results found.</div>';
            return;
        }
        data.results.forEach(result => {
            if (result.startsWith(category)) {
                const isVulnerable = result.includes('Vulnerable');
                const resultItem = document.createElement('div');
                resultItem.className = `result-item ${isVulnerable ? 'vulnerable' : 'safe'}`;
                resultItem.textContent = result;
                resultDiv.appendChild(resultItem);
            }
        });
    })
    .catch(error => {
        resultDiv.innerHTML = `<div class="alert alert-danger">Scan failed: ${error.message}</div>`;
        console.error('Error:', error);
    });
}
