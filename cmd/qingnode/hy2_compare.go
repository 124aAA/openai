package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"qingnode/internal/probe"
)

// The ordinary probe comparison remains exact. This explicit entry binds the
// only allowed configuration difference to an existing performance plan.
func (a *app) hy2Compare(args []string) error {
	f := fs("hy2 compare")
	planPath := f.String("plan", "", "已保存的HY2方案JSON")
	beforePath := f.String("before", "", "使用方案前的自动probe报告")
	afterPath := f.String("after", "", "使用方案后的自动probe报告")
	out := f.String("out", "", "新JSON比较文件；省略输出到终端")
	if err := parse(f, args); err != nil {
		return err
	}
	if *planPath == "" || *beforePath == "" || *afterPath == "" {
		return errors.New("须提供--plan、--before和--after，不能手工改写报告中的配置摘要")
	}
	plan, err := readHY2Plan(*planPath)
	if err != nil {
		return err
	}
	planSHA, err := hy2PlanSHA(plan)
	if err != nil {
		return err
	}
	before, err := probe.ReadReport(*beforePath)
	if err != nil {
		return fmt.Errorf("读取前报告：%w", err)
	}
	after, err := probe.ReadReport(*afterPath)
	if err != nil {
		return fmt.Errorf("读取后报告：%w", err)
	}
	c := probe.CompareControlled(before, after, probe.ControlledChange{
		Version: 1, PlanSHA256: planSHA, NodeID: plan.NodeID,
		BeforeClientSHA256: plan.BeforeClientSHA, AfterClientSHA256: plan.AfterClientSHA,
		BeforeServerSHA256: plan.BeforeServerSHA, AfterServerSHA256: plan.AfterServerSHA,
	})
	if *out != "" {
		if err = a.probeOutput(*out); err != nil {
			return err
		}
		if err = writeResultJSON(*out, c); err != nil {
			return err
		}
	} else {
		b, e := json.MarshalIndent(c, "", "  ")
		if e != nil {
			return e
		}
		if e = writeOutput("", b); e != nil {
			return e
		}
	}
	if !c.Comparable {
		return errors.New("两份结果不满足方案限定的比较条件；原因已保留，没有自动修改设置")
	}
	return nil
}
