import { useState, useRef, useCallback } from "react";
import client from "../api/client";

/**
 * QRDropzone — drag-and-drop file upload for QR Scanner.
 * Accepts image/* and application/pdf.
 * Calls onResults(results) with the API response on success.
 */
export default function QRDropzone({ onResults, userId = "anonymous" }) {
  const [isDragging, setIsDragging] = useState(false);
  const [preview, setPreview]       = useState(null);
  const [fileName, setFileName]     = useState("");
  const [loading, setLoading]       = useState(false);
  const [error, setError]           = useState("");
  const inputRef = useRef(null);

  const handleFile = useCallback(async (file) => {
    if (!file) return;
    setError("");
    setFileName(file.name);

    if (file.type.startsWith("image/")) {
      const reader = new FileReader();
      reader.onload = (e) => setPreview(e.target.result);
      reader.readAsDataURL(file);
    } else {
      setPreview(null);
    }

    const endpoint = file.type === "application/pdf" ? "/qr/scan-pdf" : "/qr/scan";
    const formData = new FormData();
    formData.append("file", file);
    formData.append("user_id", userId);

    setLoading(true);
    try {
      const res = await client.post(endpoint, formData, {
        headers: { "Content-Type": "multipart/form-data" },
        timeout: 60000,
      });
      onResults(res.data, file);
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || "Scan failed";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [onResults, userId]);

  const onDrop = useCallback((e) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  }, [handleFile]);

  const onDragOver = (e) => { e.preventDefault(); setIsDragging(true); };
  const onDragLeave = ()  => setIsDragging(false);

  return (
    <div className="space-y-4">
      <div
        onDrop={onDrop}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onClick={() => inputRef.current?.click()}
        className={`
          relative border-2 border-dashed rounded-xl p-8 cursor-pointer
          flex flex-col items-center justify-center text-center transition-all
          ${isDragging
            ? "border-[#E8470A] bg-[#E8470A]/10 scale-[1.01]"
            : "border-[#2C2C2E] bg-[#1C1C1E] hover:border-[#E8470A]/60 hover:bg-[#E8470A]/5"}
        `}
        style={{ minHeight: 160 }}
      >
        <input
          ref={inputRef}
          type="file"
          accept="image/*,application/pdf"
          className="hidden"
          onChange={(e) => handleFile(e.target.files[0])}
        />
        {loading ? (
          <>
            <div className="w-8 h-8 border-2 border-[#E8470A] border-t-transparent rounded-full animate-spin mb-3" />
            <p className="text-sm text-gray-400">Scanning for QR codes…</p>
          </>
        ) : (
          <>
            <svg className="w-10 h-10 mb-3 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" />
              <rect x="3" y="14" width="7" height="7" rx="1" />
              <path d="M14 14h2v2h-2zM18 14h3v2h-3zM14 18h2v3h-2zM18 18h3v3h-3z" />
            </svg>
            <p className="text-sm font-medium text-gray-300">
              Drop an image or PDF here, or <span className="text-[#E8470A]">click to browse</span>
            </p>
            <p className="text-xs text-gray-500 mt-1">JPEG · PNG · WEBP · PDF — max 10 MB</p>
          </>
        )}
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-700 rounded-lg px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {preview && !loading && (
        <div className="rounded-xl overflow-hidden border border-[#2C2C2E] bg-[#1C1C1E]">
          <p className="text-xs text-gray-500 px-3 pt-2 pb-1">{fileName}</p>
          <img src={preview} alt="Uploaded preview" className="w-full max-h-64 object-contain" />
        </div>
      )}
    </div>
  );
}
