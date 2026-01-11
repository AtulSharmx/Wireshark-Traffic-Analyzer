// bhai, this small BCA project by Atul Sharma
// made during college nights, tested with chai ☕
// now supports loading tshark JSON (client-side) to show real results

(function(){
  const btn = document.getElementById('analyzeBtn');
  const btnText = document.getElementById('btnText');
  const results = document.getElementById('results');
  const pcap = document.getElementById('pcap');
  const jsonInput = document.getElementById('jsonInput');
  const loadMsg = document.getElementById('loadMsg');

  // parsed data if user loads a tshark JSON
  let parsed = null;

  // helper: try many common layer names
  function getField(layers, keys){
    for (let k of keys){
      if (layers[k]) return Array.isArray(layers[k]) ? layers[k][0] : layers[k];
    }
    return null;
  }

  // parse tshark -T json output (array of packets)
  function parseTsharkJson(arr){
    const rowsMap = new Map();
    let synCount = 0;
    const synBySrc = {};
    let telnetFound = false;
    let pktCount = 0;

    (arr || []).forEach(pkt => {
      const layers = (pkt._source && pkt._source.layers) ? pkt._source.layers : (pkt.layers || {});
      const src = getField(layers, ['ip.src','ipv4.src','ip.src_host','ipv6.src']) || getField(layers,['eth.src']) || 'unknown';
      const dst = getField(layers, ['ip.dst','ipv4.dst','ip.dst_host','ipv6.dst']) || getField(layers,['eth.dst']) || 'unknown';

      const tcpDst = getField(layers, ['tcp.dstport','tcp.dstport.value']);
      const udpDst = getField(layers, ['udp.dstport','udp.dstport.value']);

      const dport = tcpDst || udpDst || '';
      const proto = tcpDst ? 'TCP' : (udpDst ? 'UDP' : (getField(layers,['frame.protocols']) || '').toUpperCase());

      const tcpSyn = getField(layers, ['tcp.flags_syn','tcp.flags_syn.value','tcp.flags','tcp.flags.value']) || '';
      const isSyn = (String(tcpSyn).indexOf('1') !== -1) || (String(tcpSyn).indexOf('0x02') !== -1);
      if (isSyn){
        synCount++;
        synBySrc[src] = (synBySrc[src] || 0) + 1;
      }

      if (dport === '23' || String(dport).includes(':23')) telnetFound = true;

      const key = `${src}|${dst}:${dport}|${proto}`;
      const ex = rowsMap.get(key) || {src, dst: (dport ? (dst + ':' + dport) : dst), proto: proto, count:0};
      ex.count++;
      rowsMap.set(key, ex);

      pktCount++;
    });

    const rows = Array.from(rowsMap.values()).sort((a,b)=>b.count - a.count);
    rows.forEach(r => {
      if (r.proto === 'TCP'){
        if (r.dst.endsWith(':23')) r.proto = 'TCP/Telnet';
        else if (r.dst.endsWith(':80')) r.proto = 'TCP/HTTP';
        else r.proto = 'TCP';
      } else if (r.proto === 'UDP'){
        if (r.dst.endsWith(':53')) r.proto = 'UDP/DNS';
        else r.proto = 'UDP';
      }
    });

    const topSynSrc = Object.keys(synBySrc).sort((a,b)=> (synBySrc[b]||0)-(synBySrc[a]||0))[0] || '192.168.1.100';

    return {packetCount: pktCount, synCount, topSynSrc, telnetFound, rows};
  }

  // bhai: show spinner and disable button so user no double click
  function showLoading(){
    btn.disabled = true;
    btnText.innerHTML = '<span class="spinner" aria-hidden="true"></span>ANALYSING...';
  }
  // chalo, reset button after analysis
  function resetBtn(){
    btn.disabled = false;
    btnText.textContent = 'ANALYZE TRAFFIC';
  }

  // when user uploads a JSON from tshark
  jsonInput.addEventListener('change', function(){
    const f = this.files && this.files[0];
    if (!f) return;
    const r = new FileReader();
    r.onload = function(e){
      try{
        const data = JSON.parse(e.target.result);
        parsed = parseTsharkJson(data);
        loadMsg.style.display = 'block';
        loadMsg.textContent = `Loaded ${parsed.packetCount} packets from ${f.name}`;
        loadMsg.style.color = 'var(--lime)';
      }catch(err){
        parsed = null;
        loadMsg.style.display = 'block';
        loadMsg.textContent = 'Invalid tshark JSON file';
        loadMsg.style.color = '#ffc107';
      }
    };
    r.readAsText(f);
  });

  btn.addEventListener('click', function(){
    if (btn.disabled) return;
    showLoading();

    // fake analysis delay 800ms - pretending to check packets, bhai
    setTimeout(function(){
      // if parsed data available, use it to fill UI
      if (parsed){
        const threatH3 = document.querySelector('.threat h3');
        const threatP = document.querySelector('.threat p');
        threatH3.textContent = `🚨 HIGH SEVERITY - TCP SYN Flood ${parsed.synCount} packets from ${parsed.topSynSrc}`;
        threatP.textContent = parsed.telnetFound ? 'Telnet Port 23 = DANGER unencrypted password!' : 'Telnet Port 23 = Not seen';

        // populate table
        const tbody = document.querySelector('table tbody');
        tbody.innerHTML = '';
        const top = parsed.rows.slice(0, 10);
        top.forEach(r => {
          const tr = document.createElement('tr');
          const risk = (r.proto.indexOf('Telnet')>-1) ? '<span class="badge crit">CRITICAL</span>' : (r.proto==='TCP/HTTP' ? '<span class="badge mon">MONITOR</span>' : '<span class="badge norm">NORMAL</span>');
          const action = (r.proto.indexOf('Telnet')>-1) ? 'Block Port 23' : (r.proto==='TCP/HTTP' ? 'Check logs' : 'OK');
          tr.innerHTML = `<td style="font-family:monospace;font-weight:700">${r.src}</td><td style="font-family:monospace">${r.dst}</td><td>${r.proto}</td><td>${r.count}</td><td>${risk}</td><td>${action}</td>`;
          tbody.appendChild(tr);
        });
      }

      results.style.display = 'block';
      results.setAttribute('aria-hidden','false');
      results.scrollIntoView({behavior:'smooth', block:'start'});
      resetBtn();
    }, 800);
  });

  pcap.addEventListener('keydown', function(e){
    if (e.key === 'Enter') btn.click();
  });

  // No console logs to keep console clean
})();