use pyo3::prelude::*;
use pyo3::types::PyDict;
use netscope_core::capture::CaptureEngine;
use netscope_core::models::Packet;
use netscope_core::filter::{Filter, dns_qry_name};

#[pyclass]
#[derive(Clone)]
pub struct PyDnsInfo {
    #[pyo3(get)]
    pub query_name: Option<String>,
}

#[pyclass]
#[derive(Clone)]
pub struct PyPacket {
    #[pyo3(get)]
    pub timestamp: String,
    #[pyo3(get)]
    pub src: Option<String>,
    #[pyo3(get)]
    pub dst: Option<String>,
    #[pyo3(get)]
    pub src_port: Option<u16>,
    #[pyo3(get)]
    pub dst_port: Option<u16>,
    #[pyo3(get)]
    pub protocol: String,
    #[pyo3(get)]
    pub length: usize,
    #[pyo3(get)]
    pub summary: String,
    #[pyo3(get)]
    pub dns: Option<PyDnsInfo>,
}

impl PyPacket {
    fn from_core(pkt: Packet) -> Self {
        let dns_query = dns_qry_name(&pkt);
        let dns_info = dns_query.map(|name| PyDnsInfo { query_name: Some(name) });
        
        PyPacket {
            timestamp: pkt.timestamp.format("%Y-%m-%d %H:%M:%S%.6f").to_string(),
            src: pkt.src_addr.map(|a| a.to_string()),
            dst: pkt.dst_addr.map(|a| a.to_string()),
            src_port: pkt.src_port,
            dst_port: pkt.dst_port,
            protocol: pkt.protocol.to_string(),
            length: pkt.length,
            summary: pkt.summary,
            dns: dns_info,
        }
    }
}

#[pyclass]
pub struct Capture {
    filepath: String,
}

fn read_packets_offline(filepath: &str) -> PyResult<Vec<Packet>> {
    let (tx, rx) = crossbeam_channel::unbounded();
    let mut engine = CaptureEngine::new();
    engine.start_offline(filepath, None, None, tx)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Failed to start offline capture: {}", e)))?;

    let mut packets = Vec::new();
    while let Ok(pkt) = rx.recv() {
        packets.push(pkt);
    }
    engine.stop();
    Ok(packets)
}

#[pymethods]
impl Capture {
    #[new]
    fn new(filepath: String) -> Self {
        Capture { filepath }
    }

    fn filter(&self, filter_expr: &str) -> PyResult<Vec<PyPacket>> {
        let packets = read_packets_offline(&self.filepath)?;
        let filter = Filter::parse(filter_expr)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        let mut result = Vec::new();
        for pkt in packets {
            if filter.matches(&pkt) {
                result.push(PyPacket::from_core(pkt));
            }
        }
        Ok(result)
    }

    fn to_dataframe(&self, py: Python) -> PyResult<PyObject> {
        let packets = read_packets_offline(&self.filepath)?;
        let list = pyo3::types::PyList::empty(py);
        
        for pkt in packets {
            let py_pkt = PyPacket::from_core(pkt);
            let dict = PyDict::new(py);
            dict.set_item("timestamp", py_pkt.timestamp)?;
            dict.set_item("src", py_pkt.src)?;
            dict.set_item("dst", py_pkt.dst)?;
            dict.set_item("src_port", py_pkt.src_port)?;
            dict.set_item("dst_port", py_pkt.dst_port)?;
            dict.set_item("protocol", py_pkt.protocol)?;
            dict.set_item("length", py_pkt.length)?;
            dict.set_item("summary", py_pkt.summary)?;
            
            let dns_query = py_pkt.dns.and_then(|d| d.query_name);
            dict.set_item("dns_query_name", dns_query)?;
            
            list.append(dict)?;
        }
        
        let pandas = py.import("pandas")
            .map_err(|e| pyo3::exceptions::PyImportError::new_err(format!("Pandas is required for to_dataframe(): {}", e)))?;
        let df = pandas.call_method1("DataFrame", (list,))?;
        Ok(df.to_object(py))
    }

    fn carve_files(&self, py: Python) -> PyResult<Vec<PyObject>> {
        let packets = read_packets_offline(&self.filepath)?;
        let mut all_payload = Vec::new();
        for pkt in &packets {
            all_payload.extend_from_slice(&pkt.data);
        }
        
        let carved = netscope_core::forensics::carve_files(&all_payload);
        let mut results = Vec::new();
        for item in carved {
            let dict = PyDict::new(py);
            dict.set_item("filename", item.filename)?;
            dict.set_item("file_type", item.file_type)?;
            dict.set_item("start_offset", item.start_offset)?;
            dict.set_item("size", item.size)?;
            
            let py_meta = PyDict::new(py);
            for (k, v) in item.metadata {
                py_meta.set_item(k, v)?;
            }
            dict.set_item("metadata", py_meta)?;
            results.push(dict.to_object(py));
        }
        Ok(results)
    }

    fn export_timeline_csv(&self) -> PyResult<String> {
        let packets = read_packets_offline(&self.filepath)?;
        let events = netscope_core::forensics::build_timeline(&packets);
        Ok(netscope_core::forensics::export_timeline_csv(&events))
    }

    fn export_timeline_json(&self) -> PyResult<String> {
        let packets = read_packets_offline(&self.filepath)?;
        let events = netscope_core::forensics::build_timeline(&packets);
        Ok(netscope_core::forensics::export_timeline_json(&events))
    }
}

#[pymodule]
fn netscope(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Capture>()?;
    m.add_class::<PyPacket>()?;
    m.add_class::<PyDnsInfo>()?;
    Ok(())
}
