#pragma once

#include "pch.h"

struct plugin_ctx_t : public plugmod_t
{
#if __NT__
	qvector<bytevec_t> certificates;
#elif __LINUX__ || __MAC__
	qvector<qstring> certificates;
#endif
	bool idaapi run(size_t arg) override;
	bool init_hook();
	~plugin_ctx_t() override;
};
