// Simple syntax highlighting for JSON and XML

/**
 * Highlight JSON
 * @param {string} json - JSON string
 * @returns {string} HTML with syntax highlighting
 */
export function highlightJSON(json) {
    // Simple regex-based highlighting
    return json
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?)/g, (match) => {
            let cls = 'json-string';
            if (/:$/.test(match)) {
                cls = 'json-key';
            }
            return `<span class="${cls}">${match}</span>`;
        })
        .replace(/\b(true|false|null)\b/g, '<span class="json-boolean">$1</span>')
        .replace(/\b(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\b/g, '<span class="json-number">$1</span>');
}

/**
 * Highlight XML
 * @param {string} xml - XML string
 * @returns {string} HTML with syntax highlighting
 */
export function highlightXML(xml) {
    return xml
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/(&lt;\/?)([\w-:]+)/g, '$1<span class="xml-tag">$2</span>')
        .replace(/([\w-:]+)=(".*?")/g, '<span class="xml-attr">$1</span>=<span class="xml-value">$2</span>');
}

// Add CSS for syntax highlighting
const style = document.createElement('style');
style.textContent = `
    .json-key {
        color: var(--accent-blue);
    }
    .json-string {
        color: var(--accent-green);
    }
    .json-number {
        color: var(--accent-yellow);
    }
    .json-boolean {
        color: var(--accent-red);
    }
    .xml-tag {
        color: var(--accent-blue);
    }
    .xml-attr {
        color: var(--accent-yellow);
    }
    .xml-value {
        color: var(--accent-green);
    }
`;
document.head.appendChild(style);

