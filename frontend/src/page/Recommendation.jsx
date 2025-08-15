import React from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';

const RecommendationsPage = () => {
  const navigate = useNavigate();

  const recommendations = [
    {
      number: "1",
      title: "Optimize location",
      description: "This means that people are going to be able to find you easily and find the information they need quickly."
    },
    {
      number: "2",
      title: "Connect Sources",
      description: "The more platforms you have synced the better, the average is about 2 platforms for businesses in your category."
    },
    {
      number: "3",
      title: "Publish data",
      description: "Against competitors in your niche, you're ranking in the 87th Percentile in your industry."
    }
  ];

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center p-6">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="max-w-4xl w-full space-y-8"
      >
        <div className="text-center space-y-4">
          <h1 className="text-4xl font-semibold text-gray-900">
            Great, we have your recommendations.
          </h1>
          <p className="text-xl text-gray-500">
            Here's what we're going to do.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-12">
          {recommendations.map((rec) => (
            <motion.div
              key={rec.number}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: Number(rec.number) * 0.2 }}
              className="bg-white rounded-2xl p-6 shadow-lg"
            >
              <div className="text-3xl font-semibold text-gray-900 mb-4">
                {rec.number}
              </div>
              <h3 className="text-xl font-medium text-gray-900 mb-2">
                {rec.title}
              </h3>
              <p className="text-gray-500">
                {rec.description}
              </p>
            </motion.div>
          ))}
        </div>

        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 1 }}
          className="flex justify-center mt-12"
        >
          <button
            onClick={() => navigate('/chat')}
            className="bg-black text-white px-8 py-3 rounded-full text-lg font-medium hover:bg-gray-900 transition-colors"
          >
            Let's Go
          </button>
        </motion.div>
      </motion.div>
    </div>
  );
};

export default RecommendationsPage;

