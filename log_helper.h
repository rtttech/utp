#ifndef LOG_HELPER_H
#define LOG_HELPER_H

//#define ENABLE_UTP_LOG

#ifdef ENABLE_UTP_LOG

#define SPDLOG_TRACE_ON
#define SPDLOG_DEBUG_ON

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

#define SPDLOG_INFO(logger, ...) logger->info(__VA_ARGS__)
#define SPDLOG_ERROR(logger, ...) logger->error(__VA_ARGS__)

#define DECLARE_LOG(n, f) static auto logger = spdlog::basic_logger_mt(n, f, true);

#else

#define DECLARE_LOG(n, f) ;

#define SPDLOG_TRACE(logger, ...) ;
#define SPDLOG_DEBUG(logger, ...) ;
#define SPDLOG_INFO(logger, ...) ;
#define SPDLOG_ERROR(logger, ...) ;

#endif

#define LOG_TRACE SPDLOG_TRACE
#define LOG_DEBUG SPDLOG_INFO
#define LOG_INFO SPDLOG_INFO
#define LOG_ERROR SPDLOG_ERROR



class LogHelper
{
public:
	LogHelper()
	{
#ifdef ENABLE_UTP_LOG
		spdlog::set_level(spdlog::level::trace);
		spdlog::flush_every(std::chrono::seconds(1));
#endif
	}
	~LogHelper() {}
};

#endif
