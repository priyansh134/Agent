import React, { useState, useEffect } from "react";
import PropTypes from "prop-types"; // For prop type validation
import { Mic } from "lucide-react";

export function QueryInput({ onQueryChange, query, isLoading }) {
  const [isListening, setIsListening] = useState(false);
  const [recognition, setRecognition] = useState(null);

  useEffect(() => {
    // Check if the browser supports speech recognition
    if ("webkitSpeechRecognition" in window) {
      const recognitionInstance = new webkitSpeechRecognition();
      recognitionInstance.continuous = true;
      recognitionInstance.interimResults = false;
      recognitionInstance.lang = "en-US";

      // Capture the recognized speech and set it to the query
      recognitionInstance.onresult = (event) => {
        const transcript = event.results[0][0].transcript;
        onQueryChange(transcript);
        setIsListening(false);
      };

      recognitionInstance.onerror = () => {
        setIsListening(false);
      };

      recognitionInstance.onend = () => {
        setIsListening(false);
      };

      setRecognition(recognitionInstance);
    }
  }, [onQueryChange]);

  const toggleVoiceInput = () => {
    if (!recognition) return;

    if (isListening) {
      recognition.stop();
      setIsListening(false);
    } else {
      recognition.start();
      setIsListening(true);
    }
  };

  return (
    <div className="flex items-center">
      <button
        type="button"
        onClick={toggleVoiceInput}
        className={`p-2 rounded-full transition-colors ${
          isListening
            ? "text-red-500 hover:text-red-400 bg-red-500/10"
            : "text-gray-400 hover:text-white hover:bg-gray-700"
        }`}
      >
        <Mic className="w-5 h-5" />
      </button>
    </div>
  );
}

// Prop type validation for JavaScript
QueryInput.propTypes = {
  onQueryChange: PropTypes.func.isRequired,
  query: PropTypes.string.isRequired,
  isLoading: PropTypes.bool.isRequired,
};
