package json_utils

import (
	logrus "github.com/sirupsen/logrus"
)

type JsonConfig struct{
	Loggr     *logrus.Logger
	AllowNull bool
}

type JsonOption func(jcfg *JsonConfig)

func (jcfg *JsonConfig) ApplyJsonOptions(joptList ...JsonOption) *JsonConfig {
	for _, joptFn := range joptList {
		joptFn(jcfg)
	}
	return jcfg
}

func WithLogger(loggr *logrus.Logger) JsonOption {
        return func(jcfg *JsonConfig) {
                jcfg.Loggr = loggr
        }
}

func WithAllowNull(allowNull bool) JsonOption {
        return func(jcfg *JsonConfig) {
                jcfg.AllowNull = allowNull
        }
}
