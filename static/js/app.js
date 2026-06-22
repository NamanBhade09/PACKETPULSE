// PacketPulse - Frontend Logic Engine
document.addEventListener("DOMContentLoaded", () => {
    // UI Elements
    const interfaceSelect = document.getElementById("interface-select");
    const filterInput = document.getElementById("filter-input");
    const btnStart = document.getElementById("btn-start");
    const btnStop = document.getElementById("btn-stop");
    const btnExport = document.getElementById("btn-export");
    const btnClear = document.getElementById("btn-clear");
    
    const statusDot = document.getElementById("status-dot");
    const statusText = document.getElementById("status-text");
    const captureTimer = document.getElementById("capture-timer");
    
    const metricTotal = document.getElementById("metric-total-packets");
    const metricData = document.getElementById("metric-data-size");
    const metricRate = document.getElementById("metric-packet-rate");
    
    const protoDistribution = document.getElementById("proto-distribution");
    const topSources = document.getElementById("top-sources");
    const topDestinations = document.getElementById("top-destinations");
    
    const btnShowSrc = document.getElementById("btn-show-src");
    const btnShowDst = document.getElementById("btn-show-dst");
    
    const packetSearch = document.getElementById("packet-search");
    const regexSearchCheck = document.getElementById("regex-search-check");
    const packetTableBody = document.getElementById("packet-table-body");
    const tableScrollContainer = document.querySelector(".table-scroll-container");
    
    const detailEmptyState = document.getElementById("detail-empty-state");
    const treeContainer = document.getElementById("tree-container");
    const hexContainer = document.getElementById("hex-container");
    const payloadContainerWrapper = document.getElementById("payload-container-wrapper");
    const tabButtons = document.querySelectorAll(".tab-btn");
    const tabPanes = document.querySelectorAll(".tab-pane");

    // IDS Console Elements
    const alertsPanel = document.getElementById("alerts-panel");
    const alertsCount = document.getElementById("alerts-count");
    const alertsList = document.getElementById("alerts-list");
    const btnToggleAlerts = document.getElementById("btn-toggle-alerts");

    // State Variables
    let isCapturing = false;
    let lastPacketId = null;
    let pollInterval = null;
    let timerInterval = null;
    let elapsedSeconds = 0;
    let packetsInMemory = [];
    let alertsInMemory = new Set();
    let selectedPacketId = null;
    let isAutoScrolling = true;

    // Helper: Escape HTML characters
    const escapeHtml = (text) => {
        if (text === null || text === undefined) return "";
        return String(text)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    };

    // Helper: Formats bytes size
    const formatBytes = (bytes) => {
        if (bytes === 0) return "0.00 B";
        const k = 1024;
        const sizes = ["B", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    };

    // Helper: JSON Syntax Highlighter
    const syntaxHighlightJson = (jsonObj) => {
        let json = JSON.stringify(jsonObj, undefined, 4);
        json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g, (match) => {
            let cls = 'json-value-number';
            if (/^"/.test(match)) {
                if (/:$/.test(match)) {
                    cls = 'json-key';
                } else {
                    cls = 'json-value-string';
                }
            } else if (/true|false/.test(match)) {
                cls = 'json-value-boolean';
            } else if (/null/.test(match)) {
                cls = 'json-value-null';
            }
            return `<span class="${cls}">${match}</span>`;
        });
    };

    // Load available interfaces
    const loadInterfaces = async () => {
        try {
            const res = await fetch("/api/interfaces");
            const data = await res.json();
            
            interfaceSelect.innerHTML = "";
            if (data.length === 0) {
                interfaceSelect.innerHTML = `<option value="">No interfaces found</option>`;
                return;
            }
            
            data.forEach(iface => {
                const opt = document.createElement("option");
                opt.value = iface.id;
                opt.textContent = iface.name;
                if (iface.is_loopback && !interfaceSelect.value) {
                    opt.selected = true;
                }
                interfaceSelect.appendChild(opt);
            });
        } catch (err) {
            console.error("Failed to load interfaces:", err);
            interfaceSelect.innerHTML = `<option value="">Error loading interfaces</option>`;
        }
    };

    // Synchronize UI State with Backend
    const syncStatus = async () => {
        try {
            const res = await fetch("/api/status");
            const status = await res.json();
            
            if (status.running) {
                isCapturing = true;
                btnStart.disabled = true;
                btnStop.disabled = false;
                interfaceSelect.disabled = true;
                filterInput.disabled = true;
                
                interfaceSelect.value = status.interface;
                filterInput.value = status.filter;
                
                statusDot.className = "status-dot active";
                statusText.textContent = "SNIFFING TRAFFIC...";
                
                startPolling();
                startTimer(true);
            } else {
                isCapturing = false;
                btnStart.disabled = false;
                btnStop.disabled = true;
                interfaceSelect.disabled = false;
                filterInput.disabled = false;
                
                statusDot.className = "status-dot";
                statusText.textContent = "SYSTEM IDLE";
            }
        } catch (err) {
            console.error("Error syncing status:", err);
        }
    };

    // Sidebar IP Talker Tab Toggling
    btnShowSrc.addEventListener("click", () => {
        btnShowSrc.classList.add("active");
        btnShowDst.classList.remove("active");
        topSources.style.display = "block";
        topDestinations.style.display = "none";
    });

    btnShowDst.addEventListener("click", () => {
        btnShowDst.classList.add("active");
        btnShowSrc.classList.remove("active");
        topDestinations.style.display = "block";
        topSources.style.display = "none";
    });

    // Toggle Alerts Console collapse
    btnToggleAlerts.addEventListener("click", () => {
        const isCollapsed = alertsPanel.classList.contains("collapsed");
        if (isCollapsed) {
            alertsPanel.classList.remove("collapsed");
            btnToggleAlerts.textContent = "Hide Alerts";
        } else {
            alertsPanel.classList.add("collapsed");
            btnToggleAlerts.textContent = "Show Alerts";
        }
    });

    // Start live packet polling
    const startPolling = () => {
        if (pollInterval) clearInterval(pollInterval);
        
        pollInterval = setInterval(async () => {
            try {
                let url = "/api/packets";
                if (lastPacketId) {
                    url += `?after=${lastPacketId}`;
                }
                
                const res = await fetch(url);
                const data = await res.json();
                
                if (!data.running && isCapturing) {
                    stopCaptureUI();
                }
                
                // Process packets
                if (data.packets && data.packets.length > 0) {
                    renderPackets(data.packets);
                    lastPacketId = data.packets[data.packets.length - 1].id;
                    btnExport.disabled = false;
                }
                
                // Process Security Alerts
                if (data.alerts && data.alerts.length > 0) {
                    renderAlerts(data.alerts);
                }
                
                // Update metrics
                metricTotal.textContent = data.stats.total.toLocaleString();
                metricData.textContent = formatBytes(data.stats.bytes_transferred);
                
                const rate = data.duration > 0 ? Math.round(data.stats.total / data.duration) : 0;
                metricRate.textContent = `${rate} pps`;
                
                updateSidebarStats(data.stats);
                
            } catch (err) {
                console.error("Polling error:", err);
            }
        }, 800);
    };

    // Stop live packet polling
    const stopPolling = () => {
        if (pollInterval) {
            clearInterval(pollInterval);
            pollInterval = null;
        }
    };

    // Timer functions
    const startTimer = (resume = false) => {
        if (timerInterval) clearInterval(timerInterval);
        if (!resume) elapsedSeconds = 0;
        
        timerInterval = setInterval(() => {
            elapsedSeconds++;
            const hrs = String(Math.floor(elapsedSeconds / 3600)).padStart(2, "0");
            const mins = String(Math.floor((elapsedSeconds % 3600) / 60)).padStart(2, "0");
            const secs = String(elapsedSeconds % 60).padStart(2, "0");
            captureTimer.textContent = `${hrs}:${mins}:${secs}`;
        }, 1000);
    };

    const stopTimer = () => {
        if (timerInterval) {
            clearInterval(timerInterval);
            timerInterval = null;
        }
    };

    // Render packets to live table
    const renderPackets = (newPackets) => {
        const placeholder = packetTableBody.querySelector(".placeholder-row");
        if (placeholder) placeholder.remove();
        
        newPackets.forEach(pkt => {
            packetsInMemory.push(pkt);
            
            // Check client-side filter
            const filterText = packetSearch.value.trim().toLowerCase();
            let matchesFilter = true;
            
            if (filterText) {
                if (regexSearchCheck.checked) {
                    try {
                        const regex = new RegExp(filterText, "i");
                        matchesFilter = regex.test(pkt.src) || 
                                        regex.test(pkt.dst) || 
                                        regex.test(pkt.protocol) || 
                                        regex.test(pkt.summary);
                    } catch (e) {
                        matchesFilter = pkt.src.toLowerCase().includes(filterText) ||
                                        pkt.dst.toLowerCase().includes(filterText) ||
                                        pkt.protocol.toLowerCase().includes(filterText) ||
                                        pkt.summary.toLowerCase().includes(filterText);
                    }
                } else {
                    matchesFilter = pkt.src.toLowerCase().includes(filterText) ||
                                    pkt.dst.toLowerCase().includes(filterText) ||
                                    pkt.protocol.toLowerCase().includes(filterText) ||
                                    pkt.summary.toLowerCase().includes(filterText);
                }
            }
            
            const date = new Date(pkt.timestamp * 1000);
            const timeStr = date.toTimeString().split(" ")[0] + "." + String(date.getMilliseconds()).padStart(3, "0");
            
            const tr = document.createElement("tr");
            tr.id = `pkt-${pkt.id}`;
            tr.className = "new-packet-row";
            if (!matchesFilter) {
                tr.style.display = "none";
            }
            
            tr.addEventListener("click", () => selectPacket(pkt.id));
            
            let badgeClass = "badge-unknown";
            const p = pkt.protocol.toUpperCase();
            if (p === "TCP") badgeClass = "badge-tcp";
            else if (p === "UDP") badgeClass = "badge-udp";
            else if (p === "ICMP" || p === "ICMPV6") badgeClass = "badge-icmp";
            else if (p === "DNS") badgeClass = "badge-dns";
            else if (p === "HTTP") badgeClass = "badge-http";
            else if (p === "TLS") badgeClass = "badge-tls";
            else if (p === "ARP") badgeClass = "badge-arp";
            
            tr.innerHTML = `
                <td>${packetsInMemory.length}</td>
                <td>${timeStr}</td>
                <td title="${pkt.src}">${pkt.src}</td>
                <td title="${pkt.dst}">${pkt.dst}</td>
                <td><span class="badge ${badgeClass}">${pkt.protocol}</span></td>
                <td>${pkt.length} B</td>
                <td title="${escapeHtml(pkt.summary)}">${escapeHtml(pkt.summary)}</td>
            `;
            
            packetTableBody.appendChild(tr);
            
            setTimeout(() => {
                tr.classList.remove("new-packet-row");
            }, 600);
        });
        
        const maxRows = 500;
        const rows = packetTableBody.querySelectorAll("tr");
        if (rows.length > maxRows) {
            for (let i = 0; i < rows.length - maxRows; i++) {
                rows[i].remove();
            }
        }
        
        if (isAutoScrolling) {
            tableScrollContainer.scrollTop = tableScrollContainer.scrollHeight;
        }
    };

    // Render IDS Security Alerts
    const renderAlerts = (alerts) => {
        let newAlertAdded = false;
        
        alerts.forEach(alert => {
            if (alertsInMemory.has(alert.id)) return;
            
            alertsInMemory.add(alert.id);
            newAlertAdded = true;
            
            const emptyAlertsPlaceholder = alertsList.querySelector(".empty-state-alerts");
            if (emptyAlertsPlaceholder) emptyAlertsPlaceholder.remove();
            
            const date = new Date(alert.timestamp * 1000);
            const timeStr = date.toTimeString().split(" ")[0];
            
            const item = document.createElement("div");
            item.className = "alert-item";
            item.innerHTML = `
                <div class="alert-meta">
                    <div class="alert-title-row">
                        <span class="alert-severity severity-${alert.severity.toLowerCase()}">${alert.severity}</span>
                        <span class="alert-type">${alert.type}</span>
                        <span class="alert-time">${timeStr}</span>
                    </div>
                    <div class="alert-desc">${escapeHtml(alert.summary)}</div>
                </div>
                <button class="btn-inspect-alert" data-packet-id="${alert.packet_id}">Locate Packet</button>
            `;
            
            item.querySelector(".btn-inspect-alert").addEventListener("click", () => {
                jumpToPacket(alert.packet_id);
            });
            
            alertsList.appendChild(item);
        });
        
        if (newAlertAdded) {
            alertsCount.textContent = `${alertsInMemory.size} Alerts`;
            alertsCount.style.background = "var(--neon-red)";
            alertsCount.style.color = "#fff";
            
            if (alertsPanel.classList.contains("collapsed")) {
                alertsPanel.classList.remove("collapsed");
                btnToggleAlerts.textContent = "Hide Alerts";
            }
        }
    };

    // Locate packet in table view, highlight, and inspect
    const jumpToPacket = (pktId) => {
        selectPacket(pktId);
        const row = document.getElementById(`pkt-${pktId}`);
        if (row) {
            row.scrollIntoView({ behavior: "smooth", block: "center" });
            row.classList.add("flagged-alert");
            setTimeout(() => {
                row.classList.remove("flagged-alert");
            }, 3000);
        } else {
            alert("Packet has been pruned from live table memory.");
        }
    };

    // Handle user manual scroll behavior
    tableScrollContainer.addEventListener("scroll", () => {
        const threshold = 50;
        const currentScroll = tableScrollContainer.scrollTop + tableScrollContainer.clientHeight;
        const maxScroll = tableScrollContainer.scrollHeight;
        isAutoScrolling = (maxScroll - currentScroll) <= threshold;
    });

    // Update sidebar statistics charts and tables
    const updateSidebarStats = (stats) => {
        protoDistribution.innerHTML = "";
        const protocols = stats.protocols;
        const total = stats.total;
        
        if (total === 0) {
            protoDistribution.innerHTML = `<div class="empty-state">No packets captured yet</div>`;
            return;
        }
        
        const sortedProtos = Object.entries(protocols).sort((a, b) => b[1] - a[1]);
        sortedProtos.forEach(([proto, count]) => {
            const pct = ((count / total) * 100).toFixed(1);
            let barColor = "bg-other";
            const p = proto.toUpperCase();
            if (p === "TCP") barColor = "bg-tcp";
            else if (p === "UDP") barColor = "bg-udp";
            else if (p === "ICMP" || p === "ICMPV6") barColor = "bg-icmp";
            else if (p === "DNS") barColor = "bg-dns";
            
            const barItem = document.createElement("div");
            barItem.className = "proto-bar-item";
            barItem.innerHTML = `
                <div class="proto-bar-label">
                    <span class="proto-label-name">${proto}</span>
                    <span class="proto-label-val">${count} (${pct}%)</span>
                </div>
                <div class="proto-bar-track">
                    <div class="proto-bar-fill ${barColor}" style="width: ${pct}%"></div>
                </div>
            `;
            protoDistribution.appendChild(barItem);
        });
        
        // Sources List
        topSources.innerHTML = "";
        const sortedSources = Object.entries(stats.sources);
        if (sortedSources.length === 0) {
            topSources.innerHTML = `<div class="empty-state">Waiting for traffic...</div>`;
        } else {
            const maxVal = sortedSources[0][1];
            sortedSources.forEach(([ip, count]) => {
                const pct = ((count / maxVal) * 100).toFixed(0);
                const row = document.createElement("div");
                row.className = "talker-item";
                row.innerHTML = `
                    <div class="talker-info">
                        <span class="talker-ip" title="${ip}">${ip}</span>
                        <span class="talker-count">${count}</span>
                    </div>
                    <div class="talker-bar" style="width: ${pct}%"></div>
                `;
                topSources.appendChild(row);
            });
        }
        
        // Destinations List
        topDestinations.innerHTML = "";
        const sortedDests = Object.entries(stats.destinations);
        if (sortedDests.length === 0) {
            topDestinations.innerHTML = `<div class="empty-state">Waiting for traffic...</div>`;
        } else {
            const maxVal = sortedDests[0][1];
            sortedDests.forEach(([ip, count]) => {
                const pct = ((count / maxVal) * 100).toFixed(0);
                const row = document.createElement("div");
                row.className = "talker-item";
                row.innerHTML = `
                    <div class="talker-info">
                        <span class="talker-ip" title="${ip}">${ip}</span>
                        <span class="talker-count">${count}</span>
                    </div>
                    <div class="talker-bar" style="width: ${pct}%"></div>
                `;
                topDestinations.appendChild(row);
            });
        }
    };

    // Selecting a packet for Deep Packet Inspection
    const selectPacket = async (pktId) => {
        const activeRow = packetTableBody.querySelector(".selected");
        if (activeRow) activeRow.classList.remove("selected");
        
        const row = document.getElementById(`pkt-${pktId}`);
        if (row) row.classList.add("selected");
        
        selectedPacketId = pktId;
        
        try {
            const res = await fetch(`/api/packet/${pktId}`);
            if (!res.ok) throw new Error("Packet detail request failed");
            const data = await res.json();
            
            detailEmptyState.style.display = "none";
            
            // Render Tab 1: Protocol Dissection Tree
            renderDissectionTree(data);
            
            // Render Tab 2: Hex / ASCII dump
            renderHexDump(data.hex, data.ascii);
            
            // Render Tab 3: Advanced Decoded Payload
            renderPayloadExtended(data.decoded_payload);
            
        } catch (err) {
            console.error("Error loading packet details:", err);
            treeContainer.innerHTML = `<div class="error">Failed to inspect packet: ${err.message}</div>`;
        }
    };

    // Renders the protocol dissection accordion tree
    const renderDissectionTree = (pktData) => {
        treeContainer.innerHTML = "";
        
        if (pktData.src_resolved && pktData.src_resolved !== pktData.src) {
            const infoDiv = document.createElement("div");
            infoDiv.className = "tree-layer";
            infoDiv.innerHTML = `
                <div class="tree-layer-header" style="color: var(--neon-green)">Address Hostname Mapping</div>
                <div class="tree-layer-fields">
                    <span class="tree-field-name">Source Name:</span>
                    <span class="tree-field-value">${pktData.src_resolved}</span>
                    <span class="tree-field-name">Destination Name:</span>
                    <span class="tree-field-value">${pktData.dst_resolved}</span>
                </div>
            `;
            treeContainer.appendChild(infoDiv);
        }
        
        Object.entries(pktData.details).forEach(([layerName, fields]) => {
            const layerDiv = document.createElement("div");
            layerDiv.className = "tree-layer";
            
            const header = document.createElement("div");
            header.className = "tree-layer-header";
            header.textContent = layerName;
            header.addEventListener("click", () => {
                layerDiv.classList.toggle("collapsed");
            });
            
            const fieldsContainer = document.createElement("div");
            fieldsContainer.className = "tree-layer-fields";
            
            Object.entries(fields).forEach(([fieldName, val]) => {
                const nameSpan = document.createElement("span");
                nameSpan.className = "tree-field-name";
                nameSpan.textContent = fieldName;
                
                const valSpan = document.createElement("span");
                valSpan.className = "tree-field-value";
                valSpan.textContent = val;
                
                fieldsContainer.appendChild(nameSpan);
                fieldsContainer.appendChild(valSpan);
            });
            
            layerDiv.appendChild(header);
            layerDiv.appendChild(fieldsContainer);
            treeContainer.appendChild(layerDiv);
        });
    };

    // Renders the interactive hex + ASCII columns
    const renderHexDump = (hexLines, asciiLines) => {
        hexContainer.innerHTML = "";
        let linesHtml = "";
        
        for (let i = 0; i < hexLines.length; i++) {
            const hexLine = hexLines[i];
            const asciiLine = asciiLines[i];
            const bytes = hexLine.split(" ");
            
            const offset = (i * 16).toString(16).padStart(4, "0").toUpperCase();
            let bytesHtml = "";
            let charsHtml = "";
            
            for (let b = 0; b < 16; b++) {
                const byteIdx = i * 16 + b;
                const byteVal = bytes[b] || "  ";
                const charVal = asciiLine[b] || " ";
                
                bytesHtml += `<span class="hex-byte" data-index="${byteIdx}">${byteVal}</span>`;
                charsHtml += `<span class="hex-char" data-index="${byteIdx}">${escapeHtml(charVal)}</span>`;
            }
            
            linesHtml += `
                <div class="hex-line">
                    <span class="hex-offset">${offset}</span>
                    <div class="hex-bytes">${bytesHtml}</div>
                    <div class="hex-ascii-text">${charsHtml}</div>
                </div>
            `;
        }
        
        hexContainer.innerHTML = linesHtml;
        
        hexContainer.addEventListener("mouseover", (e) => {
            const idx = e.target.getAttribute("data-index");
            if (idx !== null) {
                hexContainer.querySelectorAll(`[data-index="${idx}"]`).forEach(el => {
                    el.classList.add("highlight");
                });
            }
        });
        
        hexContainer.addEventListener("mouseout", (e) => {
            const idx = e.target.getAttribute("data-index");
            if (idx !== null) {
                hexContainer.querySelectorAll(`[data-index="${idx}"]`).forEach(el => {
                    el.classList.remove("highlight");
                });
            }
        });
    };

    // Advanced Payload decoders UI renderer
    const renderPayloadExtended = (payloadObj) => {
        payloadContainerWrapper.innerHTML = "";
        
        if (!payloadObj || payloadObj.type === "empty") {
            const el = document.createElement("pre");
            el.className = "decoded-payload-container";
            el.style.color = "var(--text-muted)";
            el.textContent = "[No application layer payload extracted]";
            payloadContainerWrapper.appendChild(el);
            return;
        }

        // 1. Render HTTP Decoded Payload
        if (payloadObj.type === "http") {
            const box = document.createElement("div");
            box.className = "http-payload-box";
            
            const reqLine = document.createElement("div");
            reqLine.className = "http-request-line";
            reqLine.textContent = payloadObj.request_line;
            box.appendChild(reqLine);
            
            if (payloadObj.headers && Object.keys(payloadObj.headers).length > 0) {
                const tbl = document.createElement("div");
                tbl.className = "http-headers-table";
                
                Object.entries(payloadObj.headers).forEach(([k, v]) => {
                    const name = document.createElement("span");
                    name.className = "http-header-name";
                    name.textContent = `${k}:`;
                    const val = document.createElement("span");
                    val.className = "http-header-value";
                    val.textContent = v;
                    tbl.appendChild(name);
                    tbl.appendChild(val);
                });
                box.appendChild(tbl);
            }
            
            if (payloadObj.body) {
                const bodyBox = document.createElement("div");
                bodyBox.className = "http-body-box";
                bodyBox.innerHTML = `<div class="http-body-title">Entity Body</div>`;
                
                const bodyContainer = document.createElement("pre");
                bodyContainer.className = "decoded-payload-container";
                
                if (payloadObj.body_json) {
                    bodyContainer.innerHTML = syntaxHighlightJson(payloadObj.body_json);
                } else {
                    bodyContainer.textContent = payloadObj.body;
                }
                bodyBox.appendChild(bodyContainer);
                box.appendChild(bodyBox);
            }
            payloadContainerWrapper.appendChild(box);
        }
        
        // 2. Render DNS Decoded Payload
        else if (payloadObj.type === "dns") {
            const box = document.createElement("div");
            box.className = "dns-payload-box";
            
            const header = document.createElement("div");
            header.className = "dns-header-info";
            header.innerHTML = `
                <div class="dns-header-item">Type: <span>${payloadObj.qr}</span></div>
                <div class="dns-header-item">Return Code: <span>${payloadObj.rcode}</span></div>
            `;
            box.appendChild(header);
            
            if (payloadObj.queries && payloadObj.queries.length > 0) {
                const sec = document.createElement("div");
                sec.innerHTML = `<div class="dns-section-title">Queries</div>`;
                const tbl = document.createElement("table");
                tbl.className = "dns-table";
                tbl.innerHTML = `
                    <thead>
                        <tr>
                            <th>Query Name</th>
                            <th>Type</th>
                            <th>Class</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${payloadObj.queries.map(q => `
                            <tr>
                                <td>${escapeHtml(q.name)}</td>
                                <td>${q.type}</td>
                                <td>${q.class}</td>
                            </tr>
                        `).join("")}
                    </tbody>
                `;
                sec.appendChild(tbl);
                box.appendChild(sec);
            }
            
            if (payloadObj.answers && payloadObj.answers.length > 0) {
                const sec = document.createElement("div");
                sec.innerHTML = `<div class="dns-section-title">Answers (Resource Records)</div>`;
                const tbl = document.createElement("table");
                tbl.className = "dns-table";
                tbl.innerHTML = `
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Value (RData)</th>
                            <th>TTL</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${payloadObj.answers.map(ans => `
                            <tr>
                                <td>${escapeHtml(ans.name)}</td>
                                <td>${ans.type}</td>
                                <td>${escapeHtml(ans.rdata)}</td>
                                <td>${ans.ttl}s</td>
                            </tr>
                        `).join("")}
                    </tbody>
                `;
                sec.appendChild(tbl);
                box.appendChild(sec);
            }
            payloadContainerWrapper.appendChild(box);
        }
        
        // 3. Render JSON Decoded Payload
        else if (payloadObj.type === "json") {
            const bodyContainer = document.createElement("pre");
            bodyContainer.className = "decoded-payload-container";
            bodyContainer.innerHTML = syntaxHighlightJson(payloadObj.content);
            payloadContainerWrapper.appendChild(bodyContainer);
        }
        
        // 4. Plaintext fallback
        else if (payloadObj.type === "text") {
            const bodyContainer = document.createElement("pre");
            bodyContainer.className = "decoded-payload-container";
            bodyContainer.textContent = payloadObj.content;
            payloadContainerWrapper.appendChild(bodyContainer);
        }
        
        // 5. Binary format payload display
        else if (payloadObj.type === "binary") {
            const container = document.createElement("div");
            container.style.display = "flex";
            container.style.flexDirection = "column";
            container.style.gap = "8px";
            
            const meta = document.createElement("div");
            meta.style.fontSize = "0.72rem";
            meta.style.color = "var(--text-secondary)";
            meta.innerHTML = `Binary Data: <strong>${payloadObj.length} Bytes</strong>`;
            container.appendChild(meta);
            
            const hexPre = document.createElement("pre");
            hexPre.className = "decoded-payload-container";
            hexPre.style.color = "var(--text-secondary)";
            
            let dispText = "";
            for (let i = 0; i < payloadObj.hex.length; i += 32) {
                const hexChunk = payloadObj.hex.substring(i, i + 32);
                const asciiChunk = payloadObj.ascii.substring(i / 2, (i + 32) / 2);
                
                let hexParts = [];
                for (let j = 0; j < hexChunk.length; j += 2) {
                    hexParts.push(hexChunk.substring(j, j + 2));
                }
                const offset = (i / 2).toString(16).padStart(4, "0").toUpperCase();
                dispText += `${offset}:  ${hexParts.join(" ").padEnd(48)}  ${asciiChunk}\n`;
            }
            
            hexPre.textContent = dispText;
            container.appendChild(hexPre);
            payloadContainerWrapper.appendChild(container);
        }
    };

    // Tab buttons switching logic
    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const tabId = btn.getAttribute("data-tab");
            tabButtons.forEach(b => b.classList.remove("active"));
            tabPanes.forEach(p => p.classList.remove("active"));
            
            btn.classList.add("active");
            document.getElementById(tabId).classList.add("active");
        });
    });

    // Start Sniffing Capture Trigger
    btnStart.addEventListener("click", async () => {
        const iface = interfaceSelect.value;
        const filt = filterInput.value;
        
        if (!iface) {
            alert("Please select a network interface!");
            return;
        }
        
        try {
            const res = await fetch("/api/start", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ interface: iface, filter: filt })
            });
            
            if (!res.ok) {
                const errData = await res.json();
                throw new Error(errData.error || "Capture start request failed");
            }
            
            isCapturing = true;
            btnStart.disabled = true;
            btnStop.disabled = false;
            btnExport.disabled = true;
            interfaceSelect.disabled = true;
            filterInput.disabled = true;
            
            statusDot.className = "status-dot active";
            statusText.textContent = "SNIFFING TRAFFIC...";
            
            // Reset local tables / state
            lastPacketId = null;
            packetsInMemory = [];
            alertsInMemory.clear();
            packetTableBody.innerHTML = "";
            alertsList.innerHTML = `<div class="empty-state-alerts">No threats detected. IDS engine monitoring...</div>`;
            alertsCount.textContent = "0 Alerts";
            alertsCount.style.background = "var(--border-color)";
            alertsPanel.classList.add("collapsed");
            btnToggleAlerts.textContent = "Show Alerts";
            
            selectedPacketId = null;
            detailEmptyState.style.display = "flex";
            treeContainer.innerHTML = "";
            hexContainer.innerHTML = "";
            payloadContainerWrapper.innerHTML = "";
            
            startPolling();
            startTimer();
            
        } catch (err) {
            console.error("Start capture error:", err);
            alert(`Failed to start capture: ${err.message}`);
        }
    });

    // Stop Sniffing Capture Trigger
    btnStop.addEventListener("click", async () => {
        try {
            const res = await fetch("/api/stop", { method: "POST" });
            if (!res.ok) throw new Error("Capture stop request failed");
            stopCaptureUI();
        } catch (err) {
            console.error("Stop capture error:", err);
            alert(`Failed to stop capture: ${err.message}`);
        }
    });

    const stopCaptureUI = () => {
        isCapturing = false;
        btnStart.disabled = false;
        btnStop.disabled = true;
        interfaceSelect.disabled = false;
        filterInput.disabled = false;
        
        statusDot.className = "status-dot";
        statusText.textContent = "SYSTEM IDLE";
        
        stopPolling();
        stopTimer();
    };

    // Client-side quick filter input event (Supports Regex)
    const runSearchFilter = () => {
        const filterText = packetSearch.value.trim().toLowerCase();
        const rows = packetTableBody.querySelectorAll("tr");
        
        rows.forEach((row, index) => {
            if (row.classList.contains("placeholder-row")) return;
            
            const pkt = packetsInMemory[index];
            if (!pkt) return;
            
            let matches = true;
            if (filterText) {
                if (regexSearchCheck.checked) {
                    try {
                        const regex = new RegExp(filterText, "i");
                        matches = regex.test(pkt.src) || 
                                  regex.test(pkt.dst) || 
                                  regex.test(pkt.protocol) || 
                                  regex.test(pkt.summary);
                    } catch (e) {
                        matches = pkt.src.toLowerCase().includes(filterText) ||
                                  pkt.dst.toLowerCase().includes(filterText) ||
                                  pkt.protocol.toLowerCase().includes(filterText) ||
                                  pkt.summary.toLowerCase().includes(filterText);
                    }
                } else {
                    matches = pkt.src.toLowerCase().includes(filterText) ||
                              pkt.dst.toLowerCase().includes(filterText) ||
                              pkt.protocol.toLowerCase().includes(filterText) ||
                              pkt.summary.toLowerCase().includes(filterText);
                }
            }
            row.style.display = matches ? "" : "none";
        });
    };

    packetSearch.addEventListener("input", runSearchFilter);
    regexSearchCheck.addEventListener("change", runSearchFilter);

    // Export PCAP button handler
    btnExport.addEventListener("click", () => {
        window.location.href = "/api/export";
    });

    // Clear feed button handler
    btnClear.addEventListener("click", () => {
        packetsInMemory = [];
        alertsInMemory.clear();
        packetTableBody.innerHTML = `
            <tr class="placeholder-row">
                <td colspan="7">${isCapturing ? 'Waiting for live packets...' : 'Click "Start Capture" to record live packets'}</td>
            </tr>
        `;
        
        alertsList.innerHTML = `<div class="empty-state-alerts">No threats detected. IDS engine monitoring...</div>`;
        alertsCount.textContent = "0 Alerts";
        alertsCount.style.background = "var(--border-color)";
        alertsPanel.classList.add("collapsed");
        btnToggleAlerts.textContent = "Show Alerts";
        
        metricTotal.textContent = "0";
        metricData.textContent = "0.00 B";
        metricRate.textContent = "0 pps";
        
        protoDistribution.innerHTML = `<div class="empty-state">No packets captured yet</div>`;
        topSources.innerHTML = `<div class="empty-state">Waiting for traffic...</div>`;
        topDestinations.innerHTML = `<div class="empty-state">Waiting for traffic...</div>`;
        
        selectedPacketId = null;
        detailEmptyState.style.display = "flex";
        treeContainer.innerHTML = "";
        hexContainer.innerHTML = "";
        payloadContainerWrapper.innerHTML = "";
    });

    const init = async () => {
        await loadInterfaces();
        await syncStatus();
    };
    
    init();
});
