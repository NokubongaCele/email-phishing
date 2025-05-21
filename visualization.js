document.addEventListener('DOMContentLoaded', function() {
    // Create confidence gauge chart
    createConfidenceGauge();
    
    // Create features chart
    createFeaturesChart();
    
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Setup highlights toggle
    setupHighlightsToggle();
});

function createConfidenceGauge() {
    const confidenceElement = document.getElementById('confidence-gauge');
    if (!confidenceElement) return;
    
    const confidenceScore = parseFloat(confidenceElement.getAttribute('data-confidence'));
    const isPhishing = confidenceElement.getAttribute('data-is-phishing') === 'True';
    
    // Chart configuration
    const ctx = document.getElementById('confidence-chart').getContext('2d');
    
    // Determine colors based on phishing status
    let gaugeColor;
    if (isPhishing) {
        if (confidenceScore >= 90) {
            gaugeColor = 'rgba(220, 53, 69, 0.8)'; // High confidence phishing (red)
        } else if (confidenceScore >= 70) {
            gaugeColor = 'rgba(253, 126, 20, 0.8)'; // Medium confidence phishing (orange)
        } else {
            gaugeColor = 'rgba(255, 193, 7, 0.8)'; // Low confidence phishing (yellow)
        }
    } else {
        if (confidenceScore >= 90) {
            gaugeColor = 'rgba(40, 167, 69, 0.8)'; // High confidence legitimate (green)
        } else if (confidenceScore >= 70) {
            gaugeColor = 'rgba(23, 162, 184, 0.8)'; // Medium confidence legitimate (teal)
        } else {
            gaugeColor = 'rgba(108, 117, 125, 0.8)'; // Low confidence legitimate (gray)
        }
    }
    
    // Create gauge chart
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [confidenceScore, 100 - confidenceScore],
                backgroundColor: [
                    gaugeColor,
                    'rgba(200, 200, 200, 0.2)'
                ],
                borderWidth: 0
            }]
        },
        options: {
            circumference: 180,
            rotation: -90,
            cutout: '75%',
            plugins: {
                tooltip: {
                    enabled: false
                },
                legend: {
                    display: false
                }
            },
            animation: {
                animateRotate: true,
                animateScale: true
            }
        }
    });
    
    // Add confidence percentage text in the center
    const confidenceText = document.getElementById('confidence-text');
    if (confidenceText) {
        confidenceText.textContent = `${Math.round(confidenceScore)}%`;
    }
}

function createFeaturesChart() {
    const featuresElement = document.getElementById('features-importance');
    if (!featuresElement) return;
    
    try {
        // Parse features from data attribute
        const features = JSON.parse(featuresElement.getAttribute('data-features'));
        
        // Extract top feature names and values
        const topFeatures = [];
        for (const [key, value] of Object.entries(features)) {
            // Skip non-numeric values and arrays
            if (typeof value === 'number' && !Array.isArray(value)) {
                topFeatures.push({
                    name: formatFeatureName(key),
                    value: value
                });
            }
        }
        
        // Sort by feature value (importance) and take top 10
        topFeatures.sort((a, b) => b.value - a.value);
        const topTenFeatures = topFeatures.slice(0, 10);
        
        // Prepare data for chart
        const featureNames = topTenFeatures.map(f => f.name);
        const featureValues = topTenFeatures.map(f => f.value);
        
        // Create horizontal bar chart
        const ctx = document.getElementById('features-chart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: featureNames,
                datasets: [{
                    label: 'Feature Importance',
                    data: featureValues,
                    backgroundColor: 'rgba(54, 162, 235, 0.6)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                indexAxis: 'y',
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const value = context.raw;
                                return value === 1 ? 'Present' : 
                                       value === 0 ? 'Absent' : 
                                       `Value: ${value.toFixed(2)}`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        max: 1
                    }
                }
            }
        });
    } catch (error) {
        console.error('Error creating features chart:', error);
    }
}

function formatFeatureName(name) {
    // Convert camelCase or snake_case to readable format
    return name
        .replace(/_/g, ' ')
        .replace(/([A-Z])/g, ' $1')
        .replace(/^\w/, c => c.toUpperCase());
}

function setupHighlightsToggle() {
    const toggleBtn = document.getElementById('toggle-highlights');
    const emailContent = document.getElementById('email-content-display');
    
    if (!toggleBtn || !emailContent) return;
    
    toggleBtn.addEventListener('click', function() {
        const isHighlighted = emailContent.classList.toggle('highlights-enabled');
        toggleBtn.textContent = isHighlighted ? 'Hide Highlights' : 'Show Highlights';
    });
    
    // Apply highlights to email content
    highlightSuspiciousElements();
}

function highlightSuspiciousElements() {
    const emailContent = document.getElementById('email-content-display');
    const keywordsElement = document.getElementById('suspicious-keywords');
    
    if (!emailContent || !keywordsElement) return;
    
    try {
        // Get suspicious keywords from the data attribute
        const keywords = JSON.parse(keywordsElement.getAttribute('data-keywords') || '[]');
        
        if (!keywords.length) return;
        
        // Get the original content
        let content = emailContent.innerHTML;
        
        // Highlight each keyword
        keywords.forEach(keyword => {
            if (!keyword) return;
            
            const regex = new RegExp(`(${escapeRegex(keyword)})`, 'gi');
            content = content.replace(regex, '<mark class="suspicious-keyword">$1</mark>');
        });
        
        // Highlight URLs
        const urlRegex = /(https?:\/\/[^\s<>"]+|www\.[^\s<>"]+)/gi;
        content = content.replace(urlRegex, '<mark class="suspicious-url">$1</mark>');
        
        // Update content with highlights (initially disabled)
        emailContent.innerHTML = content;
        
    } catch (error) {
        console.error('Error highlighting suspicious elements:', error);
    }
}

function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
