	if $1 $2 \
            mper_keywords.gperf >$3~; then \
	    mv $3~ $3; \
            elif $1 --version >/dev/null 2>&1; then \
	    echo "WARNING: gperf failed. $3 may not be up to date"; \
            rm $3~; \
            exit 0; \
            else \
	    echo "WARNING: gperf not installed. $3 may not be up to date"; \
            rm $3~; \
            touch $3; \
            fi